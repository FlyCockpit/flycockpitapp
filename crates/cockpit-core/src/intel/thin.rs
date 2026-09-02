//! Deterministic thinning for high-volume `path:line:content` search output.

use std::collections::{BTreeMap, BTreeSet};

const DEFAULT_TOTAL_RECORDS: usize = 200;
const DEFAULT_PER_FILE_RECORDS: usize = 12;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LineRecord {
    pub(crate) path: String,
    pub(crate) line: u64,
    pub(crate) content: String,
    original: String,
    order: usize,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ThinLimits {
    pub(crate) total_records: usize,
    pub(crate) per_file_records: usize,
}

impl Default for ThinLimits {
    fn default() -> Self {
        Self {
            total_records: DEFAULT_TOTAL_RECORDS,
            per_file_records: DEFAULT_PER_FILE_RECORDS,
        }
    }
}

#[derive(Clone, Debug)]
struct Candidate {
    record: LineRecord,
    score: i64,
}

pub(crate) fn parse_line_record(line: &str, order: usize) -> Option<LineRecord> {
    for (idx, ch) in line.char_indices() {
        if ch != ':' {
            continue;
        }
        let after = &line[idx + 1..];
        let digits_len = after.bytes().take_while(u8::is_ascii_digit).count();
        if digits_len == 0 {
            continue;
        }
        let rest = &after[digits_len..];
        let Some(sep) = rest.as_bytes().first().copied() else {
            continue;
        };
        if sep != b':' && sep != b'-' {
            continue;
        }
        let path = &line[..idx];
        if path.is_empty() {
            continue;
        }
        let Ok(line_no) = after[..digits_len].parse::<u64>() else {
            continue;
        };
        return Some(LineRecord {
            path: path.to_string(),
            line: line_no,
            content: rest[1..].trim_start().to_string(),
            original: line.to_string(),
            order,
        });
    }
    None
}

pub(crate) fn thin_line_output(
    redact: &crate::redact::RedactionTable,
    body: &str,
    query: &str,
    limits: ThinLimits,
) -> (String, bool) {
    let lines: Vec<&str> = body.lines().collect();
    let mut parsed = Vec::new();
    let mut unparsable = Vec::new();
    for (order, line) in lines.iter().enumerate() {
        match parse_line_record(line, order) {
            Some(record) => parsed.push(record),
            None => unparsable.push((order, (*line).to_string())),
        }
    }

    if parsed.is_empty() || !should_thin(&parsed, limits) {
        return (body.to_string(), false);
    }

    let query_terms = query_terms(query);
    let mut by_file: BTreeMap<String, Vec<LineRecord>> = BTreeMap::new();
    for record in parsed {
        by_file.entry(record.path.clone()).or_default().push(record);
    }

    let mut candidates = Vec::new();
    let mut kept_orders = BTreeSet::new();
    for records in by_file.values() {
        if let Some(first) = records.first() {
            kept_orders.insert(first.order);
        }
        if let Some(last) = records.last() {
            kept_orders.insert(last.order);
        }
        for record in records {
            candidates.push(Candidate {
                score: score_record(record, query, &query_terms),
                record: record.clone(),
            });
        }
    }

    candidates.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| a.record.order.cmp(&b.record.order))
    });

    let mut per_file_kept: BTreeMap<String, usize> = BTreeMap::new();
    for cand in candidates {
        if kept_orders.len() >= limits.total_records {
            break;
        }
        let count = per_file_kept
            .get(&cand.record.path)
            .copied()
            .unwrap_or_else(|| {
                by_file
                    .get(&cand.record.path)
                    .into_iter()
                    .flatten()
                    .filter(|r| kept_orders.contains(&r.order))
                    .count()
            });
        if count >= limits.per_file_records {
            continue;
        }
        if kept_orders.insert(cand.record.order) {
            per_file_kept.insert(cand.record.path, count + 1);
        }
    }

    let mut omitted_by_file: BTreeMap<String, usize> = BTreeMap::new();
    let mut all_records: Vec<LineRecord> = by_file.values().flatten().cloned().collect();
    all_records.sort_by_key(|record| record.order);

    let mut by_order: BTreeMap<usize, String> = BTreeMap::new();
    for (order, line) in unparsable {
        by_order.insert(order, line);
    }
    for record in all_records {
        if kept_orders.contains(&record.order) {
            by_order.insert(record.order, record.original);
        } else {
            *omitted_by_file.entry(record.path).or_default() += 1;
        }
    }

    // Margin-safe assembly (issue #294): the thinning drops records at
    // arbitrary interior positions, so a retained row may abut omitted
    // records on either side. A registered secret straddling such a boundary
    // — a multi-line literal spanning several retained rows included — would
    // leave a PARTIAL the downstream §7 whole-value scrub cannot match.
    // Group the retained rows into contiguous runs (consecutive `order`s,
    // no omitted record and no omission marker between), elide the unsafe
    // margin at each run edge that abets an omission (in joined raw
    // coordinates), and keep the synthetic omission markers as their own
    // rows (constants; §7 scrubs them whole).
    let last_kept_by_file = last_kept_by_file(&by_order);
    let mut rows: Vec<String> = Vec::new();
    let mut run: Vec<String> = Vec::new();
    let mut run_front_omitted = false;
    let mut run_back_omitted = false;
    let mut prev_order: Option<usize> = None;

    fn flush_run(
        redact: &crate::redact::RedactionTable,
        rows: &mut Vec<String>,
        run: &mut Vec<String>,
        front_omitted: bool,
        back_omitted: bool,
    ) {
        if run.is_empty() {
            return;
        }
        let joined = run.join("\n");
        let safe = if front_omitted {
            crate::tools::common::drop_front_margin(redact, &joined)
        } else {
            &joined[..]
        };
        let safe = if back_omitted {
            crate::tools::common::drop_back_margin(redact, safe)
        } else {
            safe
        };
        rows.extend(safe.split('\n').map(str::to_string));
        run.clear();
    }

    for (order, line) in by_order {
        let contiguous =
            prev_order.is_some_and(|p| order == p + 1) || (prev_order.is_none() && order == 0);
        if !contiguous {
            // An omitted record (or the stream head) precedes this row: close
            // the previous run with a back omission and open a front-elided one.
            if prev_order.is_some() {
                run_back_omitted = true;
            }
            flush_run(
                redact,
                &mut rows,
                &mut run,
                run_front_omitted,
                run_back_omitted,
            );
            run_front_omitted = prev_order.is_some() || order > 0;
            run_back_omitted = false;
        }
        run.push(line);
        prev_order = Some(order);
        let marker = parse_line_record(run.last().unwrap(), order).and_then(|record| {
            (last_kept_by_file.get(&record.path) == Some(&order))
                .then(|| {
                    omitted_by_file
                        .remove(&record.path)
                        .map(|count| (record.path, count))
                })
                .flatten()
        });
        if let Some((path, omitted)) = marker {
            // An omission marker is itself an emission discontinuity: even
            // when the adjacent original records were contiguous, the inserted
            // marker row splits them in the emitted text, so the run before it
            // gets the back elision and the run after it the front elision.
            run_back_omitted = true;
            flush_run(
                redact,
                &mut rows,
                &mut run,
                run_front_omitted,
                run_back_omitted,
            );
            run_front_omitted = true;
            run_back_omitted = false;
            rows.push(format!(
                "... [{omitted} more matches in {path} omitted; narrow query or path]"
            ));
        }
    }
    let trailing_omissions = !omitted_by_file.is_empty();
    if trailing_omissions {
        run_back_omitted = true;
    }
    flush_run(
        redact,
        &mut rows,
        &mut run,
        run_front_omitted,
        run_back_omitted,
    );
    for (path, omitted) in omitted_by_file {
        rows.push(format!(
            "... [{omitted} more matches in {path} omitted; narrow query or path]"
        ));
    }

    let mut out = rows.join("\n");
    if !out.is_empty() {
        out.push('\n');
    }
    (out, true)
}

fn should_thin(records: &[LineRecord], limits: ThinLimits) -> bool {
    if records.len() > limits.total_records {
        return true;
    }
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for record in records {
        let count = counts.entry(&record.path).or_default();
        *count += 1;
        if *count > limits.per_file_records {
            return true;
        }
    }
    false
}

fn query_terms(query: &str) -> Vec<String> {
    query
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .filter(|term| term.len() >= 2)
        .map(|term| term.to_ascii_lowercase())
        .collect()
}

fn score_record(record: &LineRecord, query: &str, terms: &[String]) -> i64 {
    let content = record.content.to_ascii_lowercase();
    let path = record.path.to_ascii_lowercase();
    let query_lc = query.to_ascii_lowercase();
    let mut score = 10_000i64.saturating_sub(record.order as i64);
    if !query_lc.is_empty() && content.contains(&query_lc) {
        score += 800;
    }
    for term in terms {
        if content.contains(term) {
            score += 160;
        }
        if path.contains(term) {
            score += 50;
        }
    }
    for keyword in [
        "error", "failed", "failure", "panic", "assert", "test", "todo", "fixme", "warning", "warn",
    ] {
        if content.contains(keyword) {
            score += 220;
        }
    }
    score
}

fn last_kept_by_file(rows: &BTreeMap<usize, String>) -> BTreeMap<String, usize> {
    let mut last = BTreeMap::new();
    for (order, line) in rows {
        if let Some(record) = parse_line_record(line, *order) {
            last.insert(record.path, *order);
        }
    }
    last
}

#[cfg(test)]
mod tests {
    use super::*;

    fn thin_for_test(body: &str, query: &str) -> (String, bool) {
        thin_line_output(
            &crate::redact::RedactionTable::empty(),
            body,
            query,
            ThinLimits {
                total_records: 8,
                per_file_records: 3,
            },
        )
    }

    #[test]
    fn parses_ordinary_windows_and_punctuated_paths() {
        let normal = parse_line_record("src/lib.rs:42: fn target()", 0).unwrap();
        assert_eq!(normal.path, "src/lib.rs");
        assert_eq!(normal.line, 42);
        assert_eq!(normal.content, "fn target()");

        let windows = parse_line_record("C:\\repo\\src\\lib.rs:7: error target", 0).unwrap();
        assert_eq!(windows.path, "C:\\repo\\src\\lib.rs");
        assert_eq!(windows.line, 7);

        let punct = parse_line_record("weird:file-name with spaces.rs:9: target", 0).unwrap();
        assert_eq!(punct.path, "weird:file-name with spaces.rs");
        assert_eq!(punct.line, 9);
    }

    #[test]
    fn small_result_set_is_unchanged() {
        let body = "a.rs:1: target\nb.rs:2: target\n";
        assert_eq!(thin_for_test(body, "target"), (body.to_string(), false));
    }

    #[test]
    fn unparsable_records_are_retained_conservatively() {
        let body = "not parseable\n";
        assert_eq!(thin_for_test(body, "target"), (body.to_string(), false));
    }

    #[test]
    fn large_set_keeps_scored_lines_first_last_and_omission_markers() {
        let mut body = String::new();
        for i in 1..=10 {
            let text = if i == 5 {
                "panic target failure"
            } else {
                "target filler"
            };
            body.push_str(&format!("src/a.rs:{i}: {text}\n"));
        }
        for i in 1..=4 {
            body.push_str(&format!("src/b.rs:{i}: target other\n"));
        }

        let (out, thinned) = thin_for_test(&body, "target");
        assert!(thinned);
        assert!(out.contains("src/a.rs:1:"));
        assert!(out.contains("src/a.rs:10:"));
        assert!(out.contains("src/a.rs:5: panic target failure"));
        assert!(out.contains("more matches in src/a.rs omitted"));
        assert!(out.contains("src/b.rs:1:"));
        assert!(out.contains("src/b.rs:4:"));
    }
    // A multi-line registered literal spanning a kept/omitted record boundary
    // leaves a PARTIAL the downstream whole-value scrub cannot match. The
    // run-edge margin elision must remove it (issue #294).
    #[test]
    fn thin_run_edge_elides_multi_line_straddling_secret() {
        const SECRET: &str = "HEADSECRET-0123456789\nTAILSECRET-0123456789";
        let table = crate::redact::RedactionTable::empty()
            .with_forced_literal(SECRET.to_string(), "$leak:thin".to_string())
            .unwrap();
        // First + last records are always kept; the middle (scored by the
        // query) is dropped by the total cap, so both run edges abut an
        // omission — the secret head sits at the first run's back edge and
        // its tail at the second run's front edge.
        let body = "src/a.rs:1: HEADSECRET-0123456789\nsrc/a.rs:2: TAILSECRET-0123456789 findme\nsrc/a.rs:3: filler three\n";
        let (out, thinned) = thin_line_output(
            &table,
            body,
            "findme",
            ThinLimits {
                total_records: 2,
                per_file_records: 1,
            },
        );
        assert!(thinned);
        let scrubbed = table.scrub(&out);
        assert!(
            !scrubbed.contains("HEADSECRET-0123456789"),
            "run back-edge partial leaked: {scrubbed}"
        );
        assert!(
            !scrubbed.contains("TAILSECRET-0123456789"),
            "run front-edge partial leaked: {scrubbed}"
        );
    }
}
