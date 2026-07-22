//! `/stats` roll-up query layer (GOALS §15).
//!
//! One public entry point — [`rollup`] — runs three aggregate queries
//! over the session DB and returns plain serde structs. The `cockpit
//! stats` CLI ([`crate::commands::stats`]) and the future TUI `/stats`
//! pane render from the same [`StatsRollup`]; neither owns the query
//! logic.
//!
//! All three sections are filtered by a [`StatsScope`] (current project
//! by `project_id`, or every project on the machine) and a
//! [`StatsRange`] (last 7 days, or all time). Both map to `WHERE`
//! clauses on the indexed `project_id` / `timestamp` columns
//! (`idx_ic_project_ts`, `idx_tce_project_ts`); `timestamp` is epoch
//! **seconds**.
//!
//! Cost is computed at query/display time from a [`PriceTable`] loaded
//! from `~/.cockpit/prices.json` (GOALS §15d). The insert path never
//! writes `cost_usd_micros` — editing `prices.json` re-prices all
//! history on the next query. (Backfilling the stored column is an
//! explicit future follow-up, out of scope here.)

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::db::sql::SqlColumn;

/// Number of language rows shown before the tail folds into `Other`
/// (GOALS §15c).
const LANGUAGE_TOP_N: usize = 8;

/// Seconds in the `7d` range window.
const SEVEN_DAYS_SECS: i64 = 7 * 86_400;

// ---- scope / range ---------------------------------------------------------

/// Which projects the roll-up covers (GOALS §15a scope toggle).
#[derive(Debug, Clone)]
pub enum StatsScope {
    /// A single project, identified by its `project_id` hash.
    Project(String),
    /// Every project recorded on this machine.
    All,
}

/// Time window the roll-up covers (GOALS §15a range toggle).
#[derive(Debug, Clone, Copy)]
pub enum StatsRange {
    /// Rows with `timestamp >= now - 7 days`.
    Last7Days,
    /// No lower time bound.
    AllTime,
}

impl StatsRange {
    /// Inclusive lower bound on `timestamp` (epoch seconds) for this
    /// range, evaluated against `now`. `AllTime` is `0` (the epoch),
    /// which selects every row.
    fn since_epoch(self, now: i64) -> i64 {
        match self {
            StatsRange::Last7Days => now - SEVEN_DAYS_SECS,
            StatsRange::AllTime => 0,
        }
    }
}

/// `(WHERE-fragment, since_epoch)` for filtering a table whose timestamp
/// column is `ts_col` and project column is `project_id`. The fragment
/// is appended after an existing `WHERE`/`AND`; it always begins with
/// `timestamp >= ?` and optionally adds `AND project_id = ?`. Callers
/// bind `since_epoch` first, then the optional `project_id`.
fn scope_range_predicate(
    scope: &StatsScope,
    since_epoch: i64,
    ts_col: SqlColumn,
) -> (String, Vec<&dyn rusqlite::ToSql>) {
    let mut sql = format!("{} >= ?1", ts_col.sql());
    let mut params: Vec<&dyn rusqlite::ToSql> = Vec::new();
    // since_epoch is bound by the caller as ?1 (owned i64 lives in the
    // caller); here we only describe the project arm.
    if let StatsScope::Project(id) = scope {
        sql.push_str(" AND project_id = ?2");
        params.push(id);
    }
    let _ = since_epoch; // documented: bound positionally by the caller
    (sql, params)
}

// ---- output structs --------------------------------------------------------

/// Full roll-up: the three §15a sections plus the resolved scope/range
/// echoed back so a renderer can label the output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsRollup {
    /// `project_id` the roll-up was scoped to, or `None` for all-projects.
    pub project_id: Option<String>,
    /// Range label: `"7d"` or `"all"`.
    pub range: String,
    /// Section 1 — token spend per model (GOALS §15a.1).
    pub tokens: TokenSpend,
    /// Section 2 — tool-call recovery per model (GOALS §15a.2).
    pub recovery: RecoverySection,
    /// Section 3 — language breakdown of file-touching tool calls
    /// (GOALS §15a.3 / §15c).
    pub language: LanguageSection,
}

/// Section 1: token spend, one row per model, plus the per-role
/// breakdown when `--by-role` was requested.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenSpend {
    /// One row per model, descending by total tokens.
    pub by_model: Vec<TokenRow>,
    /// Per-(model, provider, agent) rows; `None` unless `by_role` was
    /// requested. Agent attribution joins `tool_call_events` → the
    /// inference call's `call_id`.
    pub by_role: Option<Vec<TokenRoleRow>>,
}

/// One token-spend row (GOALS §15a.1 columns).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRow {
    pub model: String,
    pub provider: String,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cached_input_tokens: i64,
    pub cache_creation_input_tokens: i64,
    pub total_tokens: i64,
    /// Number of inference calls aggregated into this row.
    pub calls: i64,
    /// Dollar cost from `prices.json`, or `None` when no price row
    /// matched the model (rendered as `—`).
    pub cost_usd: Option<f64>,
}

/// One `--by-role` token-spend row, keyed by `(model, provider, agent)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRoleRow {
    pub model: String,
    pub provider: String,
    pub agent: String,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cached_input_tokens: i64,
    pub cache_creation_input_tokens: i64,
    pub total_tokens: i64,
    pub calls: i64,
    pub cost_usd: Option<f64>,
}

/// Section 2: tool-call recovery per model, with the expandable
/// breakdowns the TUI needs (GOALS §15a.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoverySection {
    /// One row per model, descending by total calls.
    pub by_model: Vec<RecoveryRow>,
    /// One row per LLM steering mode, descending by total calls.
    pub by_llm_mode: Vec<RecoveryModeRow>,
    /// Per-(model, tool) breakdown for the expand-on-Enter view.
    pub by_tool: Vec<RecoveryToolRow>,
    /// Per-(model, recovery_kind, recovery_stage) breakdown.
    pub by_stage: Vec<RecoveryStageRow>,
    /// Top hard failures grouped by mode, tool, and repair shape.
    pub hard_fail_shapes: Vec<HardFailShapeRow>,
}

/// Per-model recovery summary. Percentages are 0..100 over `calls`.
///
/// Definitions (GOALS §15a): `malformed = recovered + hard_fail`;
/// `recovered` = a non-`relational_default` recovery with `hard_fail =
/// 0` (the view's `recoverable = 1`); `hard_fail` = validation failed
/// and no stage matched. Relational defaults are *not* malformed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryRow {
    pub model: String,
    pub calls: i64,
    pub recovered: i64,
    pub hard_fail: i64,
    pub malformed_pct: f64,
    pub recovered_pct: f64,
    pub hard_fail_pct: f64,
}

/// Per-LLM-mode recovery summary. Blank modes are bucketed as
/// `(unknown)` in SQL so historical rows stay counted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryModeRow {
    pub llm_mode: String,
    pub calls: i64,
    pub recovered: i64,
    pub hard_fail: i64,
    pub malformed_pct: f64,
    pub recovered_pct: f64,
    pub hard_fail_pct: f64,
}

/// Per-(model, tool) recovery counts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryToolRow {
    pub model: String,
    pub tool: String,
    pub calls: i64,
    pub recovered: i64,
    pub hard_fail: i64,
}

/// Per-(model, recovery_kind, recovery_stage) counts, e.g.
/// `edit_cascade / whitespace_normalized`. `hard_fail` rows surface as
/// `kind = "hard_fail"`, `stage = ""`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryStageRow {
    pub model: String,
    pub recovery_kind: String,
    pub recovery_stage: String,
    pub count: i64,
}

/// Hard-fail rows grouped by LLM mode, tool, and malformed-input shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardFailShapeRow {
    pub llm_mode: String,
    pub tool: String,
    pub shape_fingerprint: String,
    pub count: i64,
}

/// Section 3: language breakdown of file-touching tool calls, with
/// non-file activity reported separately (GOALS §15c / §15e).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LanguageSection {
    /// Top 8 languages + a folded `Other` row, descending by count.
    /// Percentages are over `total_file_calls`.
    pub languages: Vec<LanguageRow>,
    /// Total file-touching tool calls (rows with non-NULL `language`).
    pub total_file_calls: i64,
    /// Non-file tools (NULL `language`), one row per tool, descending by
    /// count — reported under "non-file activity," never mixed into the
    /// language bars.
    pub non_file: Vec<NonFileRow>,
}

/// One language bar (GOALS §15a.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LanguageRow {
    pub language: String,
    pub calls: i64,
    /// Share of `total_file_calls`, 0..100.
    pub pct: f64,
}

/// One non-file-tool count (`bash`, `search`, `task`, ...).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonFileRow {
    pub tool: String,
    pub calls: i64,
}

// ---- pricing (GOALS §15d) --------------------------------------------------

/// Per-model price entry from `~/.cockpit/prices.json`. All rates
/// are dollars per million tokens.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct ModelPrice {
    #[serde(default)]
    pub input_per_mtok: f64,
    #[serde(default)]
    pub output_per_mtok: f64,
    #[serde(default)]
    pub cached_input_per_mtok: f64,
    #[serde(default)]
    pub cache_creation_input_per_mtok: f64,
}

/// `~/.cockpit/prices.json` parsed into a `model -> ModelPrice` map.
/// Missing file is not an error — it yields an empty table (tokens-only
/// rendering). A malformed file warns (backticked path) and also yields
/// an empty table rather than failing the whole stats query.
#[derive(Debug, Clone, Default)]
pub struct PriceTable {
    by_model: std::collections::HashMap<String, ModelPrice>,
}

impl PriceTable {
    /// Empty table — every cost lookup returns `None`.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Load from `~/.cockpit/prices.json`. Missing file → empty table.
    /// Malformed file → warn (`tracing::warn!`) and empty table.
    pub fn load_default() -> Self {
        let Some(home) = dirs::home_dir() else {
            tracing::warn!("could not locate home dir; skipping `prices.json`");
            return Self::empty();
        };
        Self::load_from(&home.join(".cockpit").join("prices.json"))
    }

    /// Load from an explicit path. Same missing/malformed semantics as
    /// [`PriceTable::load_default`].
    pub fn load_from(path: &std::path::Path) -> Self {
        let raw = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Self::empty(),
            Err(e) => {
                tracing::warn!("could not read `{}`: {e}", path.display());
                return Self::empty();
            }
        };
        match serde_json::from_str::<std::collections::HashMap<String, ModelPrice>>(&raw) {
            Ok(by_model) => Self { by_model },
            Err(e) => {
                tracing::warn!(
                    "ignoring malformed `{}` ({e}); costs will show `—`",
                    path.display()
                );
                Self::empty()
            }
        }
    }

    /// Compute dollar cost for a token mix, or `None` when the model has
    /// no price row. Cached-read and cache-creation input tokens are billed
    /// at their own rates; the remaining `input_tokens` are billed at the
    /// input rate.
    fn cost_for(
        &self,
        model: &str,
        input_tokens: i64,
        output_tokens: i64,
        cached_input_tokens: i64,
        cache_creation_input_tokens: i64,
    ) -> Option<f64> {
        let p = self.by_model.get(model)?;
        let per = |tokens: i64, rate: f64| (tokens as f64 / 1_000_000.0) * rate;
        Some(
            per(input_tokens, p.input_per_mtok)
                + per(output_tokens, p.output_per_mtok)
                + per(cached_input_tokens, p.cached_input_per_mtok)
                + per(cache_creation_input_tokens, p.cache_creation_input_per_mtok),
        )
    }
}

// ---- the roll-up -----------------------------------------------------------

/// Run the three §15a aggregates against `conn` and return a
/// [`StatsRollup`] — the single reusable entry point both `cockpit
/// stats` and the future TUI `/stats` pane render from.
///
/// `prices` supplies the cost column (GOALS §15d); pass
/// [`PriceTable::empty`] for tokens-only. `by_role` adds the
/// per-(model, provider, agent) token breakdown. `now` is the reference
/// epoch-seconds for the range window (injected for deterministic
/// tests).
///
/// Heavy scan — drive it through [`Db::run_blocking`] (async, off the
/// executor) or [`Db::read_blocking`] (sync); the free-function shape
/// mirrors `intel::ensure_fresh_blocking` so callers own the
/// connection-acquisition strategy.
pub fn rollup(
    conn: &rusqlite::Connection,
    scope: &StatsScope,
    range: StatsRange,
    prices: &PriceTable,
    by_role: bool,
    now: i64,
) -> Result<StatsRollup> {
    let since = range.since_epoch(now);
    let tokens = query_token_spend(conn, scope, since, prices, by_role)?;
    let recovery = query_recovery(conn, scope, since)?;
    let language = query_language(conn, scope, since)?;
    Ok(StatsRollup {
        project_id: match scope {
            StatsScope::Project(id) => Some(id.clone()),
            StatsScope::All => None,
        },
        range: match range {
            StatsRange::Last7Days => "7d".to_string(),
            StatsRange::AllTime => "all".to_string(),
        },
        tokens,
        recovery,
        language,
    })
}

/// Bind `since_epoch` (as `?1`) plus the optional `project_id` (`?2`).
fn bind<'a>(since: &'a i64, extra: &[&'a dyn rusqlite::ToSql]) -> Vec<&'a dyn rusqlite::ToSql> {
    let mut v: Vec<&dyn rusqlite::ToSql> = vec![since];
    v.extend_from_slice(extra);
    v
}

// ---- section 1: token spend -------------------------------------------------

fn query_token_spend(
    conn: &rusqlite::Connection,
    scope: &StatsScope,
    since: i64,
    prices: &PriceTable,
    by_role: bool,
) -> Result<TokenSpend> {
    let (pred, extra) = scope_range_predicate(scope, since, SqlColumn::ToolCallTimestamp);

    let sql = format!(
        "SELECT model, provider,
                COALESCE(SUM(input_tokens), 0),
                COALESCE(SUM(output_tokens), 0),
                COALESCE(SUM(cached_input_tokens), 0),
                COALESCE(SUM(cache_creation_input_tokens), 0),
                COUNT(*)
           FROM inference_calls
          WHERE {pred}
          GROUP BY model, provider
          ORDER BY SUM(input_tokens + output_tokens + cached_input_tokens + cache_creation_input_tokens) DESC"
    );
    let mut stmt = conn.prepare(&sql).context("preparing token spend query")?;
    let rows = stmt
        .query_map(bind(&since, &extra).as_slice(), |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, i64>(5)?,
                r.get::<_, i64>(6)?,
            ))
        })
        .context("querying token spend")?;

    let mut by_model = Vec::new();
    for r in rows {
        let (model, provider, input, output, cached, cache_creation, calls) =
            r.context("decoding token spend row")?;
        let cost = prices.cost_for(&model, input, output, cached, cache_creation);
        by_model.push(TokenRow {
            model,
            provider,
            input_tokens: input,
            output_tokens: output,
            cached_input_tokens: cached,
            cache_creation_input_tokens: cache_creation,
            total_tokens: input + output + cached + cache_creation,
            calls,
            cost_usd: cost,
        });
    }

    let by_role = if by_role {
        Some(query_token_by_role(conn, scope, since, prices)?)
    } else {
        None
    };

    Ok(TokenSpend { by_model, by_role })
}

/// Per-(model, provider, agent) token spend. Agent attribution comes
/// from `tool_call_events` (which carries `agent`); we attribute an
/// inference call's tokens to the agent that owns its tool calls,
/// joining on `call_id`. Each `call_id` must produce at most one
/// attribution row before the join, otherwise one inference call's
/// tokens can fan out across agents. Ambiguous multi-agent call ids are
/// kept in a synthetic bucket so the total remains honest and the data
/// quality issue is visible. An inference call with no tool calls (e.g.
/// a pure-text turn) has no agent row and is therefore omitted from the
/// by-role view — the by-model totals remain the source of truth.
fn query_token_by_role(
    conn: &rusqlite::Connection,
    scope: &StatsScope,
    since: i64,
    prices: &PriceTable,
) -> Result<Vec<TokenRoleRow>> {
    // Scope/range filter the inference_calls side; collapse tool calls to
    // exactly one attribution row per call_id before joining. Same-agent
    // duplicates keep the real agent. Multi-agent call ids are malformed for
    // attribution, so place them in a stable synthetic bucket instead of
    // picking an arbitrary owner or duplicating token totals.
    let project_pred = match scope {
        StatsScope::Project(_) => " AND ic.project_id = ?2",
        StatsScope::All => "",
    };
    let sql = format!(
        "SELECT ic.model, ic.provider, agent_map.agent,
                COALESCE(SUM(ic.input_tokens), 0),
                COALESCE(SUM(ic.output_tokens), 0),
                COALESCE(SUM(ic.cached_input_tokens), 0),
                COALESCE(SUM(ic.cache_creation_input_tokens), 0),
                COUNT(*)
           FROM inference_calls ic
           JOIN (
                SELECT call_id,
                       CASE
                         WHEN COUNT(DISTINCT agent) = 1 THEN MIN(agent)
                         ELSE '(ambiguous)'
                       END AS agent
                  FROM tool_call_events
                 GROUP BY call_id
           ) AS agent_map ON agent_map.call_id = ic.call_id
          WHERE ic.timestamp >= ?1{project_pred}
          GROUP BY ic.model, ic.provider, agent_map.agent
          ORDER BY SUM(ic.input_tokens + ic.output_tokens + ic.cached_input_tokens + ic.cache_creation_input_tokens) DESC"
    );
    let (_pred, extra) = scope_range_predicate(scope, since, SqlColumn::InferenceCallTimestamp);
    let mut stmt = conn
        .prepare(&sql)
        .context("preparing by-role token query")?;
    let rows = stmt
        .query_map(bind(&since, &extra).as_slice(), |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, i64>(5)?,
                r.get::<_, i64>(6)?,
                r.get::<_, i64>(7)?,
            ))
        })
        .context("querying by-role token spend")?;
    let mut out = Vec::new();
    for r in rows {
        let (model, provider, agent, input, output, cached, cache_creation, calls) =
            r.context("decoding by-role row")?;
        let cost = prices.cost_for(&model, input, output, cached, cache_creation);
        out.push(TokenRoleRow {
            model,
            provider,
            agent,
            input_tokens: input,
            output_tokens: output,
            cached_input_tokens: cached,
            cache_creation_input_tokens: cache_creation,
            total_tokens: input + output + cached + cache_creation,
            calls,
            cost_usd: cost,
        });
    }
    Ok(out)
}

// ---- section 2: recovery ----------------------------------------------------

const HARD_FAIL_SHAPE_LIMIT: i64 = 20;

fn query_recovery(
    conn: &rusqlite::Connection,
    scope: &StatsScope,
    since: i64,
) -> Result<RecoverySection> {
    let (pred, extra) = scope_range_predicate(scope, since, SqlColumn::ToolCallTimestamp);

    // Per-model summary off the view: `recoverable` and `hard_fail` are
    // the view's computed columns (the §15g rubric in SQL); we never
    // re-derive them here.
    let summary_sql = format!(
        "SELECT model,
                COUNT(*) AS calls,
                COALESCE(SUM(recoverable), 0) AS recovered,
                COALESCE(SUM(hard_fail), 0)   AS hard_fail
           FROM tool_call_stats
          WHERE {pred}
          GROUP BY model
          ORDER BY COUNT(*) DESC"
    );
    let mut stmt = conn
        .prepare(&summary_sql)
        .context("preparing recovery summary")?;
    let rows = stmt
        .query_map(bind(&since, &extra).as_slice(), |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, i64>(3)?,
            ))
        })
        .context("querying recovery summary")?;
    let mut by_model = Vec::new();
    for r in rows {
        let (model, calls, recovered, hard_fail) = r.context("decoding recovery row")?;
        let pct = |n: i64| {
            if calls > 0 {
                n as f64 * 100.0 / calls as f64
            } else {
                0.0
            }
        };
        by_model.push(RecoveryRow {
            model,
            calls,
            recovered,
            hard_fail,
            // malformed = recovered + hard_fail (GOALS §15a).
            malformed_pct: pct(recovered + hard_fail),
            recovered_pct: pct(recovered),
            hard_fail_pct: pct(hard_fail),
        });
    }

    // Per-LLM-mode summary. Blank historical rows are kept in an
    // explicit bucket instead of disappearing from the totals.
    let mode_sql = format!(
        "SELECT COALESCE(NULLIF(llm_mode, ''), '(unknown)') AS llm_mode,
                COUNT(*) AS calls,
                COALESCE(SUM(recoverable), 0) AS recovered,
                COALESCE(SUM(hard_fail), 0)   AS hard_fail
           FROM tool_call_stats
          WHERE {pred}
          GROUP BY COALESCE(NULLIF(llm_mode, ''), '(unknown)')
          ORDER BY COUNT(*) DESC"
    );
    let mut stmt = conn
        .prepare(&mode_sql)
        .context("preparing recovery-by-llm-mode")?;
    let rows = stmt
        .query_map(bind(&since, &extra).as_slice(), |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, i64>(3)?,
            ))
        })
        .context("querying recovery-by-llm-mode")?;
    let mut by_llm_mode = Vec::new();
    for r in rows {
        let (llm_mode, calls, recovered, hard_fail) =
            r.context("decoding recovery-by-llm-mode row")?;
        let pct = |n: i64| {
            if calls > 0 {
                n as f64 * 100.0 / calls as f64
            } else {
                0.0
            }
        };
        by_llm_mode.push(RecoveryModeRow {
            llm_mode,
            calls,
            recovered,
            hard_fail,
            malformed_pct: pct(recovered + hard_fail),
            recovered_pct: pct(recovered),
            hard_fail_pct: pct(hard_fail),
        });
    }

    // Per-(model, tool) breakdown.
    let tool_sql = format!(
        "SELECT model, tool,
                COUNT(*),
                COALESCE(SUM(recoverable), 0),
                COALESCE(SUM(hard_fail), 0)
           FROM tool_call_stats
          WHERE {pred}
          GROUP BY model, tool
          ORDER BY model ASC, COUNT(*) DESC"
    );
    let mut stmt = conn
        .prepare(&tool_sql)
        .context("preparing recovery-by-tool")?;
    let rows = stmt
        .query_map(bind(&since, &extra).as_slice(), |r| {
            Ok(RecoveryToolRow {
                model: r.get(0)?,
                tool: r.get(1)?,
                calls: r.get(2)?,
                recovered: r.get(3)?,
                hard_fail: r.get(4)?,
            })
        })
        .context("querying recovery-by-tool")?;
    let by_tool = rows
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("decoding recovery-by-tool")?;

    // Per-(model, kind, stage) breakdown. Hard fails surface as a
    // synthetic `hard_fail` kind so the expand view shows them; clean
    // calls (recovery_kind NULL, hard_fail 0) are excluded.
    let stage_sql = format!(
        "SELECT model,
                CASE WHEN hard_fail = 1 THEN 'hard_fail'
                     ELSE recovery_kind END AS kind,
                CASE WHEN hard_fail = 1 THEN ''
                     ELSE COALESCE(recovery_stage, '') END AS stage,
                COUNT(*)
           FROM tool_call_stats
          WHERE ({pred}) AND (hard_fail = 1 OR recovery_kind IS NOT NULL)
          GROUP BY model, kind, stage
          ORDER BY model ASC, COUNT(*) DESC"
    );
    let mut stmt = conn
        .prepare(&stage_sql)
        .context("preparing recovery-by-stage")?;
    let rows = stmt
        .query_map(bind(&since, &extra).as_slice(), |r| {
            Ok(RecoveryStageRow {
                model: r.get(0)?,
                recovery_kind: r.get(1)?,
                recovery_stage: r.get(2)?,
                count: r.get(3)?,
            })
        })
        .context("querying recovery-by-stage")?;
    let by_stage = rows
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("decoding recovery-by-stage")?;

    // Top hard-failure shapes across mode + tool. NULL fingerprints
    // stay visible so failures without a shape can still be counted.
    let hard_fail_shape_sql = format!(
        "SELECT COALESCE(NULLIF(llm_mode, ''), '(unknown)') AS llm_mode,
                tool,
                COALESCE(shape_fingerprint, '(no fingerprint)') AS shape_fingerprint,
                COUNT(*)
           FROM tool_call_stats
          WHERE ({pred}) AND hard_fail = 1
          GROUP BY COALESCE(NULLIF(llm_mode, ''), '(unknown)'),
                   tool,
                   COALESCE(shape_fingerprint, '(no fingerprint)')
          ORDER BY COUNT(*) DESC, llm_mode ASC, tool ASC, shape_fingerprint ASC
          LIMIT {HARD_FAIL_SHAPE_LIMIT}"
    );
    let mut stmt = conn
        .prepare(&hard_fail_shape_sql)
        .context("preparing recovery-hard-fail-shapes")?;
    let rows = stmt
        .query_map(bind(&since, &extra).as_slice(), |r| {
            Ok(HardFailShapeRow {
                llm_mode: r.get(0)?,
                tool: r.get(1)?,
                shape_fingerprint: r.get(2)?,
                count: r.get(3)?,
            })
        })
        .context("querying recovery-hard-fail-shapes")?;
    let hard_fail_shapes = rows
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("decoding recovery-hard-fail-shapes")?;

    Ok(RecoverySection {
        by_model,
        by_llm_mode,
        by_tool,
        by_stage,
        hard_fail_shapes,
    })
}

// ---- section 3: language ----------------------------------------------------

fn query_language(
    conn: &rusqlite::Connection,
    scope: &StatsScope,
    since: i64,
) -> Result<LanguageSection> {
    let (pred, extra) = scope_range_predicate(scope, since, SqlColumn::ToolCallTimestamp);

    // File-touching calls: language is non-NULL. Sorted descending; the
    // tail beyond the top 8 folds into `Other` here in Rust so the SQL
    // stays a plain GROUP BY.
    let lang_sql = format!(
        "SELECT language, COUNT(*)
           FROM tool_call_events
          WHERE ({pred}) AND language IS NOT NULL
          GROUP BY language
          ORDER BY COUNT(*) DESC, language ASC"
    );
    let mut stmt = conn
        .prepare(&lang_sql)
        .context("preparing language query")?;
    let rows = stmt
        .query_map(bind(&since, &extra).as_slice(), |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
        })
        .context("querying languages")?;
    let mut raw: Vec<(String, i64)> = Vec::new();
    for r in rows {
        raw.push(r.context("decoding language row")?);
    }
    let total_file_calls: i64 = raw.iter().map(|(_, n)| n).sum();

    let mut languages: Vec<LanguageRow> = Vec::new();
    let mut other_calls: i64 = 0;
    for (i, (language, calls)) in raw.into_iter().enumerate() {
        if i < LANGUAGE_TOP_N {
            languages.push(LanguageRow {
                language,
                calls,
                pct: 0.0,
            });
        } else {
            other_calls += calls;
        }
    }
    if other_calls > 0 {
        languages.push(LanguageRow {
            language: "Other".to_string(),
            calls: other_calls,
            pct: 0.0,
        });
    }
    // Fill percentages now that totals are known.
    for row in &mut languages {
        row.pct = if total_file_calls > 0 {
            row.calls as f64 * 100.0 / total_file_calls as f64
        } else {
            0.0
        };
    }

    // Non-file activity: language NULL, grouped per tool.
    let non_file_sql = format!(
        "SELECT tool, COUNT(*)
           FROM tool_call_events
          WHERE ({pred}) AND language IS NULL
          GROUP BY tool
          ORDER BY COUNT(*) DESC, tool ASC"
    );
    let mut stmt = conn
        .prepare(&non_file_sql)
        .context("preparing non-file query")?;
    let rows = stmt
        .query_map(bind(&since, &extra).as_slice(), |r| {
            Ok(NonFileRow {
                tool: r.get(0)?,
                calls: r.get(1)?,
            })
        })
        .context("querying non-file activity")?;
    let non_file = rows
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("decoding non-file activity")?;

    Ok(LanguageSection {
        languages,
        total_file_calls,
        non_file,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;
    use crate::db::inference_calls::InferenceCallRow;
    use crate::db::tool_calls::Recovery;
    use crate::db::tool_calls::ToolCallEvent;
    use serde_json::json;
    use uuid::Uuid;

    /// Seed a session and return its id; the project_id is the literal
    /// passed (tests pass `p1`/`p2` directly rather than hashing a path).
    fn seed_session(db: &Db, project_id: &str) -> Uuid {
        let s = db.create_session(project_id, "/root", "builder").unwrap();
        s.session_id
    }

    #[allow(clippy::too_many_arguments)]
    fn ic(
        db: &Db,
        sid: Uuid,
        project_id: &str,
        model: &str,
        provider: &str,
        ts: i64,
        input: i64,
        output: i64,
        cached: i64,
    ) -> Uuid {
        ic_with_cache_creation(
            db, sid, project_id, model, provider, ts, input, output, cached, 0,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn ic_with_cache_creation(
        db: &Db,
        sid: Uuid,
        project_id: &str,
        model: &str,
        provider: &str,
        ts: i64,
        input: i64,
        output: i64,
        cached: i64,
        cache_creation: i64,
    ) -> Uuid {
        let call_id = Uuid::new_v4();
        db.insert_inference_call(&InferenceCallRow {
            call_id,
            session_id: sid,
            project_id: project_id.into(),
            project_root: "/root".into(),
            model: model.into(),
            provider: provider.into(),
            timestamp: ts,
            input_tokens: input,
            output_tokens: output,
            cached_input_tokens: cached,
            cache_creation_input_tokens: cache_creation,
            cost_usd_micros: None,
            is_utility: false,
        })
        .unwrap();
        call_id
    }

    #[allow(clippy::too_many_arguments)]
    fn tce(
        db: &Db,
        sid: Uuid,
        project_id: &str,
        call_id: Uuid,
        model: &str,
        ts: i64,
        agent: &str,
        tool: &str,
        path: Option<&str>,
        recovery: Recovery,
        hard_fail: bool,
    ) {
        tce_with_dims(
            db, sid, project_id, call_id, model, ts, agent, tool, path, recovery, hard_fail, None,
            None,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn tce_with_dims(
        db: &Db,
        sid: Uuid,
        project_id: &str,
        call_id: Uuid,
        model: &str,
        ts: i64,
        agent: &str,
        tool: &str,
        path: Option<&str>,
        recovery: Recovery,
        hard_fail: bool,
        llm_mode: Option<&str>,
        shape_fingerprint: Option<&str>,
    ) {
        db.insert_tool_call(&ToolCallEvent {
            event_id: Uuid::new_v4(),
            session_id: sid,
            call_id: call_id.to_string(),
            parent_call_id: None,
            parent_child_index: None,
            provider_item_id: None,
            provider_call_id: None,
            provider_call_id_source: None,
            wire_api: None,
            provider_family: None,
            timestamp: ts,
            model: model.into(),
            provider: "anthropic".into(),
            project_id: project_id.into(),
            project_root: "/root".into(),
            agent: agent.into(),
            tool: tool.into(),
            mcp_server: None,
            path: path.map(|s| s.to_string()),
            recovery,
            hard_fail,
            exit_code: None,
            sandbox_enabled: false,
            sandboxed: false,
            sandbox_unavailable_reason: None,
            original_input_json: json!({}),
            wire_input_json: json!({}),
            output: String::new(),
            truncated: false,
            duration_ms: 0,
            cockpit_version: None,
            llm_mode: llm_mode.map(str::to_string),
            shape_fingerprint: shape_fingerprint.map(str::to_string),
            hint: None,
        })
        .unwrap();
    }

    fn run(db: &Db, scope: StatsScope, range: StatsRange, prices: &PriceTable) -> StatsRollup {
        // now = 1_000_000 keeps the 7d window's lower bound well-defined.
        db.read_blocking(|conn| super::rollup(conn, &scope, range, prices, false, 1_000_000))
            .unwrap()
    }

    #[test]
    fn token_rollup_without_pricing() {
        let db = Db::open_in_memory().unwrap();
        let sid = seed_session(&db, "p1");
        ic_with_cache_creation(&db, sid, "p1", "opus", "anthropic", 1000, 100, 50, 10, 20);
        ic(&db, sid, "p1", "opus", "anthropic", 2000, 200, 60, 0);
        ic(&db, sid, "p1", "gpt-5", "openai", 3000, 5, 5, 0);

        let r = run(
            &db,
            StatsScope::Project("p1".into()),
            StatsRange::AllTime,
            &PriceTable::empty(),
        );
        assert_eq!(r.tokens.by_model.len(), 2);
        // opus sorts first (more total tokens).
        let opus = &r.tokens.by_model[0];
        assert_eq!(opus.model, "opus");
        assert_eq!(opus.input_tokens, 300);
        assert_eq!(opus.output_tokens, 110);
        assert_eq!(opus.cached_input_tokens, 10);
        assert_eq!(opus.cache_creation_input_tokens, 20);
        assert_eq!(opus.total_tokens, 440);
        assert_eq!(opus.calls, 2);
        assert!(opus.cost_usd.is_none(), "no prices => None");
    }

    #[test]
    fn token_rollup_with_pricing() {
        let db = Db::open_in_memory().unwrap();
        let sid = seed_session(&db, "p1");
        ic_with_cache_creation(
            &db,
            sid,
            "p1",
            "opus",
            "anthropic",
            1000,
            1_000_000,
            1_000_000,
            1_000_000,
            1_000_000,
        );

        let mut by_model = std::collections::HashMap::new();
        by_model.insert(
            "opus".to_string(),
            ModelPrice {
                input_per_mtok: 3.0,
                output_per_mtok: 15.0,
                cached_input_per_mtok: 0.3,
                cache_creation_input_per_mtok: 3.75,
            },
        );
        let prices = PriceTable { by_model };

        let r = run(
            &db,
            StatsScope::Project("p1".into()),
            StatsRange::AllTime,
            &prices,
        );
        let row = &r.tokens.by_model[0];
        // 1M input @ $3 + 1M output @ $15 + 1M cached @ $0.30
        // + 1M cache-creation @ $3.75 = $22.05.
        let cost = row.cost_usd.expect("priced model has a cost");
        assert!((cost - 22.05).abs() < 1e-9, "cost was {cost}");
    }

    #[test]
    fn recovery_percentages() {
        let db = Db::open_in_memory().unwrap();
        let sid = seed_session(&db, "p1");
        let cid = ic(&db, sid, "p1", "qwen", "local", 1000, 1, 1, 0);
        // 10 calls: 6 clean, 2 recovered (shape_repair), 1 relational
        // (not malformed), 1 hard-fail.
        for _ in 0..6 {
            tce(
                &db,
                sid,
                "p1",
                cid,
                "qwen",
                1000,
                "builder",
                "read",
                Some("a.rs"),
                Recovery::Clean,
                false,
            );
        }
        for _ in 0..2 {
            tce(
                &db,
                sid,
                "p1",
                cid,
                "qwen",
                1000,
                "builder",
                "editunlock",
                Some("a.rs"),
                Recovery::ShapeRepair {
                    stage: "wrap_bare_string",
                    path: String::new(),
                    hint: None,
                },
                false,
            );
        }
        // relational_default isn't in the Recovery enum's db_fields as a
        // distinct variant here; emulate by inserting a clean row — the
        // view treats NULL kind as recovered=0 which is what we want for
        // "not malformed". So instead test the hard_fail arm:
        tce(
            &db,
            sid,
            "p1",
            cid,
            "qwen",
            1000,
            "builder",
            "bash",
            None,
            Recovery::Clean,
            true,
        );
        // pad back to 10 with a clean call.
        tce(
            &db,
            sid,
            "p1",
            cid,
            "qwen",
            1000,
            "builder",
            "read",
            Some("b.rs"),
            Recovery::Clean,
            false,
        );

        let r = run(
            &db,
            StatsScope::Project("p1".into()),
            StatsRange::AllTime,
            &PriceTable::empty(),
        );
        let row = &r.recovery.by_model[0];
        assert_eq!(row.calls, 10);
        assert_eq!(row.recovered, 2);
        assert_eq!(row.hard_fail, 1);
        assert!((row.recovered_pct - 20.0).abs() < 1e-9);
        assert!((row.hard_fail_pct - 10.0).abs() < 1e-9);
        assert!((row.malformed_pct - 30.0).abs() < 1e-9);

        // Stage breakdown carries the shape_repair stage + the hard fail.
        let stages: Vec<_> = r.recovery.by_stage.iter().collect();
        assert!(stages.iter().any(|s| s.recovery_kind == "shape_repair"
            && s.recovery_stage == "wrap_bare_string"
            && s.count == 2));
        assert!(
            stages
                .iter()
                .any(|s| s.recovery_kind == "hard_fail" && s.count == 1)
        );
        // Per-tool breakdown present.
        assert!(
            r.recovery
                .by_tool
                .iter()
                .any(|t| t.tool == "editunlock" && t.recovered == 2)
        );
    }

    #[test]
    fn recovery_by_llm_mode_groups_and_percentages() {
        let db = Db::open_in_memory().unwrap();
        let sid = seed_session(&db, "p1");
        let cid = ic(&db, sid, "p1", "qwen", "local", 1000, 1, 1, 0);

        tce_with_dims(
            &db,
            sid,
            "p1",
            cid,
            "qwen",
            1000,
            "builder",
            "edit",
            Some("a.rs"),
            Recovery::ShapeRepair {
                stage: "wrap_bare_string",
                path: String::new(),
                hint: None,
            },
            false,
            Some("normal"),
            Some("shape-a"),
        );
        tce_with_dims(
            &db,
            sid,
            "p1",
            cid,
            "qwen",
            1000,
            "builder",
            "bash",
            None,
            Recovery::Clean,
            true,
            Some("normal"),
            Some("shape-b"),
        );
        tce_with_dims(
            &db,
            sid,
            "p1",
            cid,
            "qwen",
            1000,
            "builder",
            "read",
            Some("a.rs"),
            Recovery::Clean,
            false,
            Some("defensive"),
            None,
        );

        let r = run(
            &db,
            StatsScope::Project("p1".into()),
            StatsRange::AllTime,
            &PriceTable::empty(),
        );
        let normal = r
            .recovery
            .by_llm_mode
            .iter()
            .find(|row| row.llm_mode == "normal")
            .expect("normal mode row");
        assert_eq!(normal.calls, 2);
        assert_eq!(normal.recovered, 1);
        assert_eq!(normal.hard_fail, 1);
        assert!((normal.malformed_pct - 100.0).abs() < 1e-9);
        assert!((normal.recovered_pct - 50.0).abs() < 1e-9);
        assert!((normal.hard_fail_pct - 50.0).abs() < 1e-9);

        let defensive = r
            .recovery
            .by_llm_mode
            .iter()
            .find(|row| row.llm_mode == "defensive")
            .expect("defensive mode row");
        assert_eq!(defensive.calls, 1);
        assert_eq!(defensive.recovered, 0);
        assert_eq!(defensive.hard_fail, 0);
    }

    #[test]
    fn recovery_by_llm_mode_buckets_blank_mode_as_unknown() {
        let db = Db::open_in_memory().unwrap();
        let sid = seed_session(&db, "p1");
        let cid = ic(&db, sid, "p1", "qwen", "local", 1000, 1, 1, 0);

        tce_with_dims(
            &db,
            sid,
            "p1",
            cid,
            "qwen",
            1000,
            "builder",
            "read",
            Some("a.rs"),
            Recovery::Clean,
            false,
            Some(""),
            None,
        );

        let r = run(
            &db,
            StatsScope::Project("p1".into()),
            StatsRange::AllTime,
            &PriceTable::empty(),
        );
        let unknown = r
            .recovery
            .by_llm_mode
            .iter()
            .find(|row| row.llm_mode == "(unknown)")
            .expect("unknown mode row");
        assert_eq!(unknown.calls, 1);
    }

    #[test]
    fn recovery_hard_fail_shapes_group_by_mode_tool_fingerprint() {
        let db = Db::open_in_memory().unwrap();
        let sid = seed_session(&db, "p1");
        let cid = ic(&db, sid, "p1", "qwen", "local", 1000, 1, 1, 0);

        for _ in 0..2 {
            tce_with_dims(
                &db,
                sid,
                "p1",
                cid,
                "qwen",
                1000,
                "builder",
                "edit",
                Some("a.rs"),
                Recovery::Clean,
                true,
                Some("normal"),
                Some("shape-a"),
            );
        }
        tce_with_dims(
            &db,
            sid,
            "p1",
            cid,
            "qwen",
            1000,
            "builder",
            "bash",
            None,
            Recovery::Clean,
            true,
            Some("defensive"),
            Some("shape-b"),
        );
        tce_with_dims(
            &db,
            sid,
            "p1",
            cid,
            "qwen",
            1000,
            "builder",
            "edit",
            Some("a.rs"),
            Recovery::ShapeRepair {
                stage: "wrap_bare_string",
                path: String::new(),
                hint: None,
            },
            false,
            Some("normal"),
            Some("shape-a"),
        );

        let r = run(
            &db,
            StatsScope::Project("p1".into()),
            StatsRange::AllTime,
            &PriceTable::empty(),
        );
        assert!(
            r.recovery.hard_fail_shapes.iter().any(|row| {
                row.llm_mode == "normal"
                    && row.tool == "edit"
                    && row.shape_fingerprint == "shape-a"
                    && row.count == 2
            }),
            "expected grouped normal/edit/shape-a hard failures"
        );
        assert!(
            r.recovery.hard_fail_shapes.iter().any(|row| {
                row.llm_mode == "defensive"
                    && row.tool == "bash"
                    && row.shape_fingerprint == "shape-b"
                    && row.count == 1
            }),
            "expected grouped defensive/bash/shape-b hard failure"
        );
    }

    #[test]
    fn recovery_hard_fail_shapes_bucket_null_fingerprint() {
        let db = Db::open_in_memory().unwrap();
        let sid = seed_session(&db, "p1");
        let cid = ic(&db, sid, "p1", "qwen", "local", 1000, 1, 1, 0);

        tce_with_dims(
            &db,
            sid,
            "p1",
            cid,
            "qwen",
            1000,
            "builder",
            "bash",
            None,
            Recovery::Clean,
            true,
            Some("normal"),
            None,
        );

        let r = run(
            &db,
            StatsScope::Project("p1".into()),
            StatsRange::AllTime,
            &PriceTable::empty(),
        );
        assert!(
            r.recovery
                .hard_fail_shapes
                .iter()
                .any(|row| { row.shape_fingerprint == "(no fingerprint)" && row.count == 1 })
        );
    }

    #[test]
    fn recovery_hard_fail_shapes_limited_to_twenty() {
        let db = Db::open_in_memory().unwrap();
        let sid = seed_session(&db, "p1");
        let cid = ic(&db, sid, "p1", "qwen", "local", 1000, 1, 1, 0);

        for idx in 0..25 {
            tce_with_dims(
                &db,
                sid,
                "p1",
                cid,
                "qwen",
                1000,
                "builder",
                "edit",
                Some("a.rs"),
                Recovery::Clean,
                true,
                Some("normal"),
                Some(&format!("shape-{idx:02}")),
            );
        }

        let r = run(
            &db,
            StatsScope::Project("p1".into()),
            StatsRange::AllTime,
            &PriceTable::empty(),
        );
        assert_eq!(r.recovery.hard_fail_shapes.len(), 20);
    }

    #[test]
    fn recovery_existing_sections_unchanged_by_new_dimensions() {
        let db = Db::open_in_memory().unwrap();
        let sid = seed_session(&db, "p1");
        let cid = ic(&db, sid, "p1", "qwen", "local", 1000, 1, 1, 0);

        tce_with_dims(
            &db,
            sid,
            "p1",
            cid,
            "qwen",
            1000,
            "builder",
            "editunlock",
            Some("a.rs"),
            Recovery::ShapeRepair {
                stage: "wrap_bare_string",
                path: String::new(),
                hint: None,
            },
            false,
            Some("normal"),
            Some("shape-a"),
        );
        tce_with_dims(
            &db,
            sid,
            "p1",
            cid,
            "qwen",
            1000,
            "builder",
            "bash",
            None,
            Recovery::Clean,
            true,
            Some("defensive"),
            Some("shape-b"),
        );
        tce_with_dims(
            &db,
            sid,
            "p1",
            cid,
            "qwen",
            1000,
            "builder",
            "read",
            Some("b.rs"),
            Recovery::Clean,
            false,
            Some("normal"),
            None,
        );

        let r = run(
            &db,
            StatsScope::Project("p1".into()),
            StatsRange::AllTime,
            &PriceTable::empty(),
        );
        let model = &r.recovery.by_model[0];
        assert_eq!(model.model, "qwen");
        assert_eq!(model.calls, 3);
        assert_eq!(model.recovered, 1);
        assert_eq!(model.hard_fail, 1);
        assert!(
            r.recovery
                .by_tool
                .iter()
                .any(|row| row.tool == "editunlock" && row.recovered == 1)
        );
        assert!(r.recovery.by_stage.iter().any(|row| {
            row.recovery_kind == "shape_repair"
                && row.recovery_stage == "wrap_bare_string"
                && row.count == 1
        }));
        assert!(
            r.recovery
                .by_stage
                .iter()
                .any(|row| row.recovery_kind == "hard_fail" && row.count == 1)
        );
    }

    #[test]
    fn language_top8_and_other_folding() {
        let db = Db::open_in_memory().unwrap();
        let sid = seed_session(&db, "p1");
        let cid = ic(&db, sid, "p1", "m", "p", 1000, 1, 1, 0);
        // 9 distinct languages so one folds into Other. Use descending
        // counts so the fold target is deterministic.
        let langs = [
            ("a.rs", 10),  // Rust
            ("a.ts", 9),   // TypeScript
            ("a.py", 8),   // Python
            ("a.go", 7),   // Go
            ("a.rb", 6),   // Ruby
            ("a.java", 5), // Java
            ("a.c", 4),    // C
            ("a.md", 3),   // Markdown
            ("a.lua", 2),  // Lua -> folds to Other (9th)
        ];
        for (path, n) in langs {
            for _ in 0..n {
                tce(
                    &db,
                    sid,
                    "p1",
                    cid,
                    "m",
                    1000,
                    "builder",
                    "read",
                    Some(path),
                    Recovery::Clean,
                    false,
                );
            }
        }
        // Non-file activity.
        for _ in 0..4 {
            tce(
                &db,
                sid,
                "p1",
                cid,
                "m",
                1000,
                "builder",
                "bash",
                None,
                Recovery::Clean,
                false,
            );
        }
        for _ in 0..2 {
            tce(
                &db,
                sid,
                "p1",
                cid,
                "m",
                1000,
                "builder",
                "search",
                None,
                Recovery::Clean,
                false,
            );
        }

        let r = run(
            &db,
            StatsScope::Project("p1".into()),
            StatsRange::AllTime,
            &PriceTable::empty(),
        );
        let lang = &r.language;
        assert_eq!(lang.total_file_calls, 54);
        // 8 named + 1 Other.
        assert_eq!(lang.languages.len(), 9);
        let other = lang.languages.last().unwrap();
        assert_eq!(other.language, "Other");
        assert_eq!(other.calls, 2); // only Lua folded.
        // Top row is Rust at 10/54.
        assert_eq!(lang.languages[0].language, "Rust");
        assert!((lang.languages[0].pct - (10.0 * 100.0 / 54.0)).abs() < 1e-9);
        // Non-file reported separately, not in the bars.
        assert!(!lang.languages.iter().any(|l| l.language == "Shell"));
        assert_eq!(lang.non_file.len(), 2);
        assert_eq!(lang.non_file[0].tool, "bash");
        assert_eq!(lang.non_file[0].calls, 4);
    }

    #[test]
    fn scope_and_range_filtering() {
        let db = Db::open_in_memory().unwrap();
        let s1 = seed_session(&db, "p1");
        let s2 = seed_session(&db, "p2");
        // p1: recent + old; p2: recent only.
        ic(&db, s1, "p1", "m", "p", 1_000_000 - 100, 10, 0, 0); // in 7d
        ic(&db, s1, "p1", "m", "p", 1_000, 99, 0, 0); // old (outside 7d)
        ic(&db, s2, "p2", "m", "p", 1_000_000 - 100, 5, 0, 0); // other project

        // Scope=p1, range=all → both p1 rows.
        let r = run(
            &db,
            StatsScope::Project("p1".into()),
            StatsRange::AllTime,
            &PriceTable::empty(),
        );
        assert_eq!(r.tokens.by_model[0].input_tokens, 109);

        // Scope=p1, range=7d → only recent p1 row.
        let r = run(
            &db,
            StatsScope::Project("p1".into()),
            StatsRange::Last7Days,
            &PriceTable::empty(),
        );
        assert_eq!(r.tokens.by_model[0].input_tokens, 10);

        // Scope=all, range=all → all three projects' tokens (10+99+5).
        let r = run(
            &db,
            StatsScope::All,
            StatsRange::AllTime,
            &PriceTable::empty(),
        );
        assert_eq!(r.tokens.by_model[0].input_tokens, 114);

        // Scope=all, range=7d → recent only (10+5).
        let r = run(
            &db,
            StatsScope::All,
            StatsRange::Last7Days,
            &PriceTable::empty(),
        );
        assert_eq!(r.tokens.by_model[0].input_tokens, 15);
    }

    #[test]
    fn empty_db_renders_clean() {
        let db = Db::open_in_memory().unwrap();
        let r = run(
            &db,
            StatsScope::All,
            StatsRange::AllTime,
            &PriceTable::empty(),
        );
        assert!(r.tokens.by_model.is_empty());
        assert!(r.recovery.by_model.is_empty());
        assert!(r.language.languages.is_empty());
        assert_eq!(r.language.total_file_calls, 0);
        assert!(r.language.non_file.is_empty());
    }

    #[test]
    fn by_role_breakdown() {
        let db = Db::open_in_memory().unwrap();
        let sid = seed_session(&db, "p1");
        let cid_builder = ic(&db, sid, "p1", "m", "p", 1000, 100, 0, 0);
        let cid_docs = ic(&db, sid, "p1", "m", "p", 1000, 30, 0, 0);
        tce(
            &db,
            sid,
            "p1",
            cid_builder,
            "m",
            1000,
            "builder",
            "read",
            Some("a.rs"),
            Recovery::Clean,
            false,
        );
        tce(
            &db,
            sid,
            "p1",
            cid_docs,
            "m",
            1000,
            "docs",
            "read",
            Some("b.md"),
            Recovery::Clean,
            false,
        );

        let r = db
            .read_blocking(|conn| {
                super::rollup(
                    conn,
                    &StatsScope::Project("p1".into()),
                    StatsRange::AllTime,
                    &PriceTable::empty(),
                    true,
                    1_000_000,
                )
            })
            .unwrap();
        let roles = r.tokens.by_role.expect("by_role requested");
        assert_eq!(roles.len(), 2);
        let builder = roles.iter().find(|x| x.agent == "builder").unwrap();
        assert_eq!(builder.input_tokens, 100);
        let docs = roles.iter().find(|x| x.agent == "docs").unwrap();
        assert_eq!(docs.input_tokens, 30);
    }

    #[test]
    fn by_role_same_agent_multiple_tool_rows_count_once() {
        let db = Db::open_in_memory().unwrap();
        let sid = seed_session(&db, "p1");
        let cid = ic_with_cache_creation(&db, sid, "p1", "m", "p", 1000, 100, 20, 5, 7);
        for tool in ["read", "grep"] {
            tce(
                &db,
                sid,
                "p1",
                cid,
                "m",
                1000,
                "builder",
                tool,
                Some("a.rs"),
                Recovery::Clean,
                false,
            );
        }

        let r = db
            .read_blocking(|conn| {
                super::rollup(
                    conn,
                    &StatsScope::Project("p1".into()),
                    StatsRange::AllTime,
                    &PriceTable::empty(),
                    true,
                    1_000_000,
                )
            })
            .unwrap();
        let roles = r.tokens.by_role.expect("by_role requested");

        assert_eq!(roles.len(), 1);
        let builder = &roles[0];
        assert_eq!(builder.agent, "builder");
        assert_eq!(builder.input_tokens, 100);
        assert_eq!(builder.output_tokens, 20);
        assert_eq!(builder.cached_input_tokens, 5);
        assert_eq!(builder.cache_creation_input_tokens, 7);
        assert_eq!(builder.total_tokens, 132);
        assert_eq!(builder.calls, 1);
    }

    #[test]
    fn malformed_prices_json_yields_empty_table() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("prices.json");
        std::fs::write(&path, b"{ this is not json").unwrap();
        let table = PriceTable::load_from(&path);
        // Empty => no cost for any model, no panic.
        assert!(table.cost_for("opus", 1000, 1000, 0, 0).is_none());
    }

    #[test]
    fn missing_prices_json_yields_empty_table() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.json");
        let table = PriceTable::load_from(&path);
        assert!(table.cost_for("opus", 1000, 1000, 0, 0).is_none());
    }

    #[test]
    fn old_prices_json_defaults_cache_creation_rate_to_zero() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("prices.json");
        std::fs::write(
            &path,
            r#"{"opus":{"input_per_mtok":3.0,"output_per_mtok":15.0,"cached_input_per_mtok":0.3}}"#,
        )
        .unwrap();
        let table = PriceTable::load_from(&path);

        let cost = table
            .cost_for("opus", 1_000_000, 1_000_000, 1_000_000, 1_000_000)
            .expect("old price row still loads");
        assert!((cost - 18.3).abs() < 1e-9, "cost was {cost}");
    }
}
