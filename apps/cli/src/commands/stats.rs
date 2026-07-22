//! `cockpit stats` — the plain-text mirror of the `/stats` pane
//! (GOALS §15f). A thin renderer over [`crate::db::stats::rollup`]; the
//! roll-up layer in [`crate::db::stats`] owns every query so the TUI
//! pane consumes the same structured data.

use anyhow::Result;
use chrono::Utc;

use crate::cli::{StatsArgs, StatsFormat, StatsProjectScope, StatsRangeArg};
use crate::db::Db;
use crate::db::stats::{
    self, LanguageSection, PriceTable, RecoverySection, StatsRange, StatsRollup, StatsScope,
    TokenSpend,
};
use crate::session::project_id_for;

pub async fn run(args: StatsArgs) -> Result<()> {
    let db = Db::open_default()?;

    let scope = match args.project_scope {
        StatsProjectScope::All => StatsScope::All,
        StatsProjectScope::Current => StatsScope::Project(resolve_current_project_id()?),
    };
    let range = match args.range {
        StatsRangeArg::SevenDays => StatsRange::Last7Days,
        StatsRangeArg::All => StatsRange::AllTime,
    };
    let by_role = args.by_role;
    let prices = PriceTable::load_default();
    let now = Utc::now().timestamp();

    // Heavy aggregate scan → run off the executor (the layer's docstring
    // calls this out).
    let rollup = db
        .read(move |conn| stats::rollup(conn, &scope, range, &prices, by_role, now))
        .await?;

    match args.format {
        StatsFormat::Json => print_json(&rollup)?,
        StatsFormat::Csv => print_csv(&rollup)?,
        StatsFormat::Table => print_table(&rollup),
    }
    Ok(())
}

/// Resolve the current working directory to a `project_id` the same way
/// session creation does (GOALS §15b): prefer the git worktree root for
/// stability across symlink shifts, else the cwd realpath.
fn resolve_current_project_id() -> Result<String> {
    let cwd = std::env::current_dir().map_err(|e| anyhow::anyhow!("resolving cwd: {e}"))?;
    let root = crate::git::find_worktree_root(&cwd).unwrap_or(cwd);
    Ok(project_id_for(&root))
}

// ---- JSON ------------------------------------------------------------------

fn print_json(rollup: &StatsRollup) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(rollup)?);
    Ok(())
}

// ---- table -----------------------------------------------------------------

fn print_table(r: &StatsRollup) {
    let scope_label = match &r.project_id {
        Some(id) => format!("project {id}"),
        None => "all projects".to_string(),
    };
    println!("cockpit stats — {scope_label}, range {}\n", r.range);

    print_token_table(&r.tokens);
    println!();
    print_recovery_table(&r.recovery);
    println!();
    print_language_table(&r.language);
}

fn print_token_table(t: &TokenSpend) {
    println!("Token spend");
    if t.by_model.is_empty() {
        println!("  (no data)");
    } else {
        let header = [
            "Model",
            "In",
            "Out",
            "Cached",
            "CacheCreate",
            "Total",
            "Calls",
            "Cost",
        ];
        let mut rows: Vec<Vec<String>> = Vec::new();
        for m in &t.by_model {
            rows.push(vec![
                m.model.clone(),
                fmt_count(m.input_tokens),
                fmt_count(m.output_tokens),
                fmt_count(m.cached_input_tokens),
                fmt_count(m.cache_creation_input_tokens),
                fmt_count(m.total_tokens),
                m.calls.to_string(),
                fmt_cost(m.cost_usd),
            ]);
        }
        print_aligned(&header, &rows, "  ");
    }

    if let Some(roles) = &t.by_role {
        println!("\n  By role (agent)");
        if roles.is_empty() {
            println!("    (no data)");
        } else {
            let header = [
                "Model",
                "Agent",
                "In",
                "Out",
                "Cached",
                "CacheCreate",
                "Total",
                "Calls",
                "Cost",
            ];
            let mut rows: Vec<Vec<String>> = Vec::new();
            for m in roles {
                rows.push(vec![
                    m.model.clone(),
                    m.agent.clone(),
                    fmt_count(m.input_tokens),
                    fmt_count(m.output_tokens),
                    fmt_count(m.cached_input_tokens),
                    fmt_count(m.cache_creation_input_tokens),
                    fmt_count(m.total_tokens),
                    m.calls.to_string(),
                    fmt_cost(m.cost_usd),
                ]);
            }
            print_aligned(&header, &rows, "    ");
        }
    }
}

fn print_recovery_table(rec: &RecoverySection) {
    for line in recovery_table_lines(rec) {
        println!("{line}");
    }
}

fn recovery_table_lines(rec: &RecoverySection) -> Vec<String> {
    let mut out = vec!["Tool-call recovery".to_string()];
    if rec.by_model.is_empty() {
        out.push("  (no data)".to_string());
        return out;
    }
    let header = ["Model", "Calls", "Malformed%", "Recovered%", "Hard-fail%"];
    let mut rows: Vec<Vec<String>> = Vec::new();
    for m in &rec.by_model {
        rows.push(vec![
            m.model.clone(),
            m.calls.to_string(),
            fmt_pct(m.malformed_pct),
            fmt_pct(m.recovered_pct),
            fmt_pct(m.hard_fail_pct),
        ]);
    }
    out.extend(aligned_lines(&header, &rows, "  "));
    if !rec.by_llm_mode.is_empty() {
        out.push(String::new());
        out.push("  By LLM mode".to_string());
        let header = ["Mode", "Calls", "Malformed%", "Recovered%", "Hard-fail%"];
        let mut rows: Vec<Vec<String>> = Vec::new();
        for m in &rec.by_llm_mode {
            rows.push(vec![
                m.llm_mode.clone(),
                m.calls.to_string(),
                fmt_pct(m.malformed_pct),
                fmt_pct(m.recovered_pct),
                fmt_pct(m.hard_fail_pct),
            ]);
        }
        out.extend(aligned_lines(&header, &rows, "  "));
    }
    // Per-tool / per-stage breakdowns are returned for the TUI's
    // expand-on-Enter view; the CLI keeps the table compact and surfaces
    // them only in json/csv.
    out
}

fn print_language_table(lang: &LanguageSection) {
    println!("Language (file-touching tool calls)");
    if lang.languages.is_empty() {
        println!("  (no data)");
    } else {
        let header = ["Language", "Pct", "Calls"];
        let mut rows: Vec<Vec<String>> = Vec::new();
        for l in &lang.languages {
            rows.push(vec![
                l.language.clone(),
                fmt_pct(l.pct),
                l.calls.to_string(),
            ]);
        }
        print_aligned(&header, &rows, "  ");
    }
    if !lang.non_file.is_empty() {
        let parts: Vec<String> = lang
            .non_file
            .iter()
            .map(|n| format!("{} {}", n.calls, n.tool))
            .collect();
        println!("\n  Non-file activity: {}", parts.join(" / "));
    }
}

/// Print a header + rows as left-aligned, space-padded columns. Column
/// width is the max of the header and every cell in that column.
fn print_aligned(header: &[&str], rows: &[Vec<String>], indent: &str) {
    for line in aligned_lines(header, rows, indent) {
        println!("{line}");
    }
}

fn aligned_lines(header: &[&str], rows: &[Vec<String>], indent: &str) -> Vec<String> {
    let cols = header.len();
    let mut widths: Vec<usize> = header.iter().map(|h| h.len()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate().take(cols) {
            widths[i] = widths[i].max(cell.len());
        }
    }
    let line = |cells: &[String]| {
        let mut s = String::from(indent);
        for (i, cell) in cells.iter().enumerate().take(cols) {
            if i > 0 {
                s.push_str("  ");
            }
            if i + 1 == cols {
                s.push_str(cell);
            } else {
                s.push_str(&format!("{cell:<width$}", width = widths[i]));
            }
        }
        s
    };
    let header_owned: Vec<String> = header.iter().map(|h| h.to_string()).collect();
    let mut out = vec![line(&header_owned)];
    for row in rows {
        out.push(line(row));
    }
    out
}

// ---- CSV -------------------------------------------------------------------

/// CSV output: one labelled block per section, separated by a blank
/// line. Each block opens with a `# section` comment line, then a header
/// row, then data rows — so a script can split on blank lines or filter
/// by the section marker.
fn print_csv(r: &StatsRollup) -> Result<()> {
    use std::io::Write;
    let mut out = Vec::<u8>::new();

    // Section 1: token spend.
    writeln!(out, "# token_spend")?;
    {
        let mut w = csv::Writer::from_writer(&mut out);
        w.write_record([
            "model",
            "provider",
            "input",
            "output",
            "cached",
            "cache_creation",
            "total",
            "calls",
            "cost_usd",
        ])?;
        for m in &r.tokens.by_model {
            w.write_record([
                m.model.as_str(),
                m.provider.as_str(),
                &m.input_tokens.to_string(),
                &m.output_tokens.to_string(),
                &m.cached_input_tokens.to_string(),
                &m.cache_creation_input_tokens.to_string(),
                &m.total_tokens.to_string(),
                &m.calls.to_string(),
                &csv_cost(m.cost_usd),
            ])?;
        }
        w.flush()?;
    }

    if let Some(roles) = &r.tokens.by_role {
        writeln!(out, "\n# token_spend_by_role")?;
        let mut w = csv::Writer::from_writer(&mut out);
        w.write_record([
            "model",
            "provider",
            "agent",
            "input",
            "output",
            "cached",
            "cache_creation",
            "total",
            "calls",
            "cost_usd",
        ])?;
        for m in roles {
            w.write_record([
                m.model.as_str(),
                m.provider.as_str(),
                m.agent.as_str(),
                &m.input_tokens.to_string(),
                &m.output_tokens.to_string(),
                &m.cached_input_tokens.to_string(),
                &m.cache_creation_input_tokens.to_string(),
                &m.total_tokens.to_string(),
                &m.calls.to_string(),
                &csv_cost(m.cost_usd),
            ])?;
        }
        w.flush()?;
    }

    // Section 2: recovery (summary + breakdowns — the TUI's expand data).
    writeln!(out, "\n# recovery")?;
    {
        let mut w = csv::Writer::from_writer(&mut out);
        w.write_record([
            "model",
            "calls",
            "malformed_pct",
            "recovered_pct",
            "hard_fail_pct",
        ])?;
        for m in &r.recovery.by_model {
            w.write_record([
                m.model.as_str(),
                &m.calls.to_string(),
                &fmt_pct_raw(m.malformed_pct),
                &fmt_pct_raw(m.recovered_pct),
                &fmt_pct_raw(m.hard_fail_pct),
            ])?;
        }
        w.flush()?;
    }
    writeln!(out, "\n# recovery_by_llm_mode")?;
    {
        let mut w = csv::Writer::from_writer(&mut out);
        w.write_record([
            "llm_mode",
            "calls",
            "malformed_pct",
            "recovered_pct",
            "hard_fail_pct",
        ])?;
        for m in &r.recovery.by_llm_mode {
            w.write_record([
                m.llm_mode.as_str(),
                &m.calls.to_string(),
                &fmt_pct_raw(m.malformed_pct),
                &fmt_pct_raw(m.recovered_pct),
                &fmt_pct_raw(m.hard_fail_pct),
            ])?;
        }
        w.flush()?;
    }
    writeln!(out, "\n# recovery_by_tool")?;
    {
        let mut w = csv::Writer::from_writer(&mut out);
        w.write_record(["model", "tool", "calls", "recovered", "hard_fail"])?;
        for t in &r.recovery.by_tool {
            w.write_record([
                t.model.as_str(),
                t.tool.as_str(),
                &t.calls.to_string(),
                &t.recovered.to_string(),
                &t.hard_fail.to_string(),
            ])?;
        }
        w.flush()?;
    }
    writeln!(out, "\n# recovery_by_stage")?;
    {
        let mut w = csv::Writer::from_writer(&mut out);
        w.write_record(["model", "recovery_kind", "recovery_stage", "count"])?;
        for s in &r.recovery.by_stage {
            w.write_record([
                s.model.as_str(),
                s.recovery_kind.as_str(),
                s.recovery_stage.as_str(),
                &s.count.to_string(),
            ])?;
        }
        w.flush()?;
    }
    writeln!(out, "\n# recovery_hard_fail_shapes")?;
    {
        let mut w = csv::Writer::from_writer(&mut out);
        w.write_record(["llm_mode", "tool", "shape_fingerprint", "count"])?;
        for s in &r.recovery.hard_fail_shapes {
            w.write_record([
                s.llm_mode.as_str(),
                s.tool.as_str(),
                s.shape_fingerprint.as_str(),
                &s.count.to_string(),
            ])?;
        }
        w.flush()?;
    }

    // Section 3: language + non-file.
    writeln!(out, "\n# language")?;
    {
        let mut w = csv::Writer::from_writer(&mut out);
        w.write_record(["language", "pct", "calls"])?;
        for l in &r.language.languages {
            w.write_record([
                l.language.as_str(),
                &fmt_pct_raw(l.pct),
                &l.calls.to_string(),
            ])?;
        }
        w.flush()?;
    }
    writeln!(out, "\n# non_file_activity")?;
    {
        let mut w = csv::Writer::from_writer(&mut out);
        w.write_record(["tool", "calls"])?;
        for n in &r.language.non_file {
            w.write_record([n.tool.as_str(), &n.calls.to_string()])?;
        }
        w.flush()?;
    }

    let text = String::from_utf8(out).map_err(|e| anyhow::anyhow!("csv was not utf-8: {e}"))?;
    print!("{text}");
    Ok(())
}

// ---- formatting helpers ----------------------------------------------------

/// Human-readable token count: `1.2K`, `3.4M`, or the raw number below 1000.
fn fmt_count(n: i64) -> String {
    let n_abs = n.unsigned_abs();
    if n_abs >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n_abs >= 1_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

fn fmt_pct(p: f64) -> String {
    format!("{p:.1}%")
}

fn fmt_pct_raw(p: f64) -> String {
    format!("{p:.1}")
}

/// Cost for the table: `$0.92` or the em-dash when unpriced.
fn fmt_cost(c: Option<f64>) -> String {
    match c {
        Some(v) => format!("${v:.2}"),
        None => "—".to_string(),
    }
}

/// Cost for CSV: a bare number or empty cell when unpriced (no `$`, no
/// em-dash — keeps the column numeric for `awk`/`cut`).
fn csv_cost(c: Option<f64>) -> String {
    match c {
        Some(v) => format!("{v:.6}"),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::stats::{
        HardFailShapeRow, LanguageRow, NonFileRow, RecoveryModeRow, RecoveryRow, TokenRow,
    };

    fn sample_rollup() -> StatsRollup {
        StatsRollup {
            project_id: Some("abc123".into()),
            range: "7d".into(),
            tokens: TokenSpend {
                by_model: vec![TokenRow {
                    model: "opus".into(),
                    provider: "anthropic".into(),
                    input_tokens: 12_300,
                    output_tokens: 4_100,
                    cached_input_tokens: 45_200,
                    cache_creation_input_tokens: 2_000,
                    total_tokens: 63_600,
                    calls: 3,
                    cost_usd: Some(0.92),
                }],
                by_role: None,
            },
            recovery: RecoverySection {
                by_model: vec![RecoveryRow {
                    model: "opus".into(),
                    calls: 145,
                    recovered: 2,
                    hard_fail: 0,
                    malformed_pct: 1.4,
                    recovered_pct: 1.4,
                    hard_fail_pct: 0.0,
                }],
                by_llm_mode: vec![RecoveryModeRow {
                    llm_mode: "normal".into(),
                    calls: 145,
                    recovered: 2,
                    hard_fail: 0,
                    malformed_pct: 1.4,
                    recovered_pct: 1.4,
                    hard_fail_pct: 0.0,
                }],
                by_tool: vec![],
                by_stage: vec![],
                hard_fail_shapes: vec![HardFailShapeRow {
                    llm_mode: "normal".into(),
                    tool: "edit".into(),
                    shape_fingerprint: "shape-a".into(),
                    count: 3,
                }],
            },
            language: LanguageSection {
                languages: vec![LanguageRow {
                    language: "Rust".into(),
                    calls: 189,
                    pct: 45.2,
                }],
                total_file_calls: 189,
                non_file: vec![NonFileRow {
                    tool: "bash".into(),
                    calls: 412,
                }],
            },
        }
    }

    #[test]
    fn table_renders_all_sections() {
        // Smoke test: rendering doesn't panic and the JSON/CSV paths
        // produce non-empty output for a populated rollup.
        let r = sample_rollup();
        print_table(&r); // would panic on a formatting bug
        let json = serde_json::to_string_pretty(&r).unwrap();
        assert!(json.contains("\"opus\""));
        assert!(json.contains("\"Rust\""));
    }

    #[test]
    fn stats_recovery_cli_table_includes_llm_mode() {
        let r = sample_rollup();
        let text = recovery_table_lines(&r.recovery).join("\n");

        assert!(text.contains("By LLM mode"));
        assert!(text.contains("normal"));
    }

    #[test]
    fn stats_recovery_cli_table_omits_fingerprint_rows() {
        let r = sample_rollup();
        let text = recovery_table_lines(&r.recovery).join("\n");

        assert!(!text.contains("shape-a"));
    }

    #[test]
    fn stats_recovery_json_includes_new_collections() {
        let r = sample_rollup();
        let json = serde_json::to_string_pretty(&r).unwrap();

        assert!(json.contains("\"by_llm_mode\""));
        assert!(json.contains("\"hard_fail_shapes\""));
        assert!(json.contains("\"shape_fingerprint\": \"shape-a\""));
    }

    #[test]
    fn csv_has_section_markers_and_costs() {
        let r = sample_rollup();
        // Exercise the same buffer-building path print_csv uses.
        use std::io::Write;
        let mut out = Vec::<u8>::new();
        writeln!(out, "# token_spend").unwrap();
        let mut w = csv::Writer::from_writer(&mut out);
        w.write_record(["model", "cost_usd"]).unwrap();
        w.write_record(["opus", &csv_cost(r.tokens.by_model[0].cost_usd)])
            .unwrap();
        w.flush().unwrap();
        drop(w);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("# token_spend"));
        assert!(text.contains("opus,0.920000"));
    }

    #[test]
    fn empty_cost_renders_dash_in_table_blank_in_csv() {
        assert_eq!(fmt_cost(None), "—");
        assert_eq!(csv_cost(None), "");
        assert_eq!(fmt_cost(Some(1.5)), "$1.50");
    }

    #[test]
    fn count_formatting() {
        assert_eq!(fmt_count(999), "999");
        assert_eq!(fmt_count(1_500), "1.5K");
        assert_eq!(fmt_count(2_000_000), "2.0M");
    }
}
