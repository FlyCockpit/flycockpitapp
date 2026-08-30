//! Cross-session full-text recall query layer (`session_search` /
//! `session_read`, prompt `search-old-sessions.md`).
//!
//! Backed by the `session_fts` FTS5 virtual table (migration 0013). The
//! engine is BM25 ranking with a `last_active_at_unix_ms` recency tiebreaker; no
//! embeddings in v1. The candidate-pool seam ([`search_candidates`]
//! returns more rows than the caller's display budget) is where a future
//! embedding ranker would re-rank without changing either tool's schema.

use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use serde_json::Value;
use uuid::Uuid;

use crate::db::Db;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryCallerTrust {
    Trusted,
    Untrusted,
}

impl HistoryCallerTrust {
    fn can_read_trusted(self) -> bool {
        matches!(self, Self::Trusted)
    }
}

/// One FTS5 hit, resolved back to its thread + in-thread location. The
/// snippet is generated from canonical session text with matched literal
/// terms wrapped in the highlight delimiters.
#[derive(Debug, Clone)]
pub struct SearchHit {
    pub session_id: Uuid,
    pub short_id: Option<String>,
    pub title: Option<String>,
    /// `last_active_at_unix_ms` — the human-date source + recency
    /// tiebreaker.
    pub last_active_at_unix_ms: i64,
    /// Best snippet for this thread (matched terms highlighted).
    pub snippet: String,
    /// BM25 relevance (lower = more relevant, FTS5 convention). Kept on
    /// the hit so a future re-ranker can blend it with other signals.
    pub bm25: f64,
}

/// A message turn read back from a thread (`session_read`).
#[derive(Debug, Clone)]
pub struct ThreadTurn {
    pub seq: i64,
    /// `user` or `assistant`.
    pub role: String,
    pub text: String,
}

#[derive(Debug, Clone)]
pub struct ToolEventScanHit {
    pub session_id: Uuid,
    pub seq: i64,
    pub event_type: String,
    pub snippet: String,
}

#[derive(Debug, Clone)]
pub struct ToolEventScan {
    pub hits: Vec<ToolEventScanHit>,
    pub truncated: bool,
}

impl Db {
    /// One-off probe that the bundled SQLite actually has FTS5 compiled
    /// in. Creates a throwaway in-`temp` FTS5 table and selects against
    /// it. Returns `Ok(())` when FTS5 is usable; an explanatory error
    /// otherwise. The feature must never silently degrade to LIKE
    /// (prompt decision), so callers surface this and stop.
    pub async fn fts5_available(&self) -> Result<()> {
        self.write(move |conn| {
            conn.execute_batch(
                "CREATE VIRTUAL TABLE temp.__cockpit_fts5_probe USING fts5(x);
                 INSERT INTO temp.__cockpit_fts5_probe (x) VALUES ('cockpit');
                 DROP TABLE temp.__cockpit_fts5_probe;",
            )
            .context(
                "FTS5 is not available in this SQLite build; \
                 session_search/session_read require it and there is no LIKE fallback",
            )?;
            Ok(())
        })
        .await
    }

    /// Rank FTS5 candidates for `query`, one row per matching thread
    /// (the best-ranking snippet per session). Ordered by BM25 relevance
    /// then `last_active_at_unix_ms` recency. This is the candidate pool: callers
    /// pass a `pool` larger than their display budget so a later ranking
    /// pass (today identity; a future embedding re-ranker tomorrow) has
    /// room to reorder.
    ///
    /// Scope rules:
    ///   * `project_id = Some(p)` confines to that project; `None` is
    ///     global recall across every project.
    ///   * `exclude_session` drops the current live thread.
    ///   * archived threads (`archived_at_unix_ms IS NOT NULL`) are always
    ///     excluded — search never surfaces a soft-deleted thread.
    ///   * `since` (epoch seconds) keeps only threads active at/after it.
    pub async fn search_candidates(
        &self,
        query: &str,
        project_id: Option<&str>,
        exclude_session: Option<Uuid>,
        since: Option<i64>,
        pool: u32,
    ) -> Result<Vec<SearchHit>> {
        self.search_candidates_for_trust(
            query,
            project_id,
            exclude_session,
            since,
            pool,
            HistoryCallerTrust::Trusted,
        )
        .await
    }

    pub async fn search_candidates_for_trust(
        &self,
        query: &str,
        project_id: Option<&str>,
        exclude_session: Option<Uuid>,
        since: Option<i64>,
        pool: u32,
        caller_trust: HistoryCallerTrust,
    ) -> Result<Vec<SearchHit>> {
        let query = query.to_string();
        let project_id = project_id.map(str::to_string);
        self.read(move |conn| {
            search_candidates_inner(
                conn,
                &query,
                project_id.as_deref(),
                exclude_session,
                since,
                pool,
                caller_trust,
                None,
            )
        })
        .await
    }

    /// Search only an explicit set of sessions. The membership filter is part
    /// of the FTS query, before BM25 ordering and the bounded candidate pool,
    /// so consent-scoped callers cannot be starved by unrelated sessions.
    pub async fn search_candidates_in_sessions_for_trust(
        &self,
        query: &str,
        session_ids: &[Uuid],
        exclude_session: Option<Uuid>,
        since: Option<i64>,
        pool: u32,
        caller_trust: HistoryCallerTrust,
    ) -> Result<Vec<SearchHit>> {
        let query = query.to_string();
        let session_ids = session_ids.to_vec();
        self.read(move |conn| {
            search_candidates_inner(
                conn,
                &query,
                None,
                exclude_session,
                since,
                pool,
                caller_trust,
                Some(&session_ids),
            )
        })
        .await
    }

    /// All `user_message` / `assistant_message` turns of a thread,
    /// ordered by `seq` (oldest first). Powers `session_read`'s
    /// windowing — the tool slices this in Rust per the `read`-tool
    /// pagination conventions. Non-message events are skipped.
    pub async fn thread_turns(&self, session_id: Uuid) -> Result<Vec<ThreadTurn>> {
        self.thread_turns_for_trust(session_id, HistoryCallerTrust::Trusted)
            .await
    }

    pub async fn thread_turns_for_trust(
        &self,
        session_id: Uuid,
        caller_trust: HistoryCallerTrust,
    ) -> Result<Vec<ThreadTurn>> {
        self.read(move |conn| Self::thread_turns_conn_for_trust(conn, session_id, caller_trust))
            .await
    }

    pub fn thread_turns_conn(conn: &Connection, session_id: Uuid) -> Result<Vec<ThreadTurn>> {
        Self::thread_turns_conn_for_trust(conn, session_id, HistoryCallerTrust::Trusted)
    }

    pub fn thread_turns_conn_for_trust(
        conn: &Connection,
        session_id: Uuid,
        caller_trust: HistoryCallerTrust,
    ) -> Result<Vec<ThreadTurn>> {
        let mut stmt = conn
            .prepare(
                "SELECT seq, type, json_extract(data_json, '$.text') AS text
                   FROM session_events
                  WHERE session_id = ?1
                    AND type IN ('user_message', 'assistant_message')
                    AND (?2 OR model_trust IS NULL OR model_trust <> 'trusted')
                  ORDER BY seq ASC",
            )
            .context("preparing thread_turns")?;
        let rows = stmt
            .query_map(
                params![session_id.to_string(), caller_trust.can_read_trusted()],
                |row| {
                    let kind: String = row.get("type")?;
                    let role = match kind.as_str() {
                        "assistant_message" => "assistant",
                        _ => "user",
                    }
                    .to_string();
                    let text: Option<String> = row.get("text")?;
                    Ok(ThreadTurn {
                        seq: row.get("seq")?,
                        role,
                        text: text.unwrap_or_default(),
                    })
                },
            )
            .context("querying thread_turns")?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.context("decoding thread turn")?);
        }
        Ok(out)
    }

    /// `seq`s within a thread whose message text matches `query` (FTS5),
    /// oldest first. `session_read` centers its window on these. Empty
    /// when the thread has no textual match.
    pub async fn thread_match_seqs(&self, session_id: Uuid, query: &str) -> Result<Vec<i64>> {
        self.thread_match_seqs_for_trust(session_id, query, HistoryCallerTrust::Trusted)
            .await
    }

    pub async fn thread_match_seqs_for_trust(
        &self,
        session_id: Uuid,
        query: &str,
        caller_trust: HistoryCallerTrust,
    ) -> Result<Vec<i64>> {
        let query = query.to_string();
        self.read(move |conn| {
            let Some(match_query) = literal_fts_match_query(&query) else {
                return Ok(Vec::new());
            };
            let mut stmt = conn
                .prepare(
                    "SELECT f.seq
                       FROM session_fts
                       JOIN session_fts_docs AS f ON f.rowid = session_fts.rowid
                       JOIN session_events AS e ON e.seq = f.seq
                      WHERE session_fts MATCH ?1
                        AND f.row_kind = 'message'
                        AND f.session_id = ?2
                        AND (?3 OR e.model_trust IS NULL OR e.model_trust <> 'trusted')
                      ORDER BY f.seq ASC",
                )
                .context("preparing thread_match_seqs")?;
            let rows = stmt
                .query_map(
                    params![
                        match_query,
                        session_id.to_string(),
                        caller_trust.can_read_trusted()
                    ],
                    |row| row.get::<_, i64>("seq"),
                )
                .context("querying thread_match_seqs")?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r.context("decoding match seq")?);
            }
            Ok(out)
        })
        .await
    }

    pub async fn compaction_lineage_sessions(&self, session_id: Uuid) -> Result<Vec<Uuid>> {
        self.read(move |conn| compaction_lineage_sessions_conn(conn, session_id))
            .await
    }

    pub async fn search_lineage_candidates(
        &self,
        query: &str,
        session_id: Uuid,
        pool: u32,
        caller_trust: HistoryCallerTrust,
    ) -> Result<Vec<SearchHit>> {
        let query = query.to_string();
        self.read(move |conn| {
            let lineage = compaction_lineage_sessions_conn(conn, session_id)?;
            search_candidates_in_sessions_inner(conn, &query, &lineage, pool, caller_trust)
        })
        .await
    }

    pub async fn scan_tool_events_in_sessions(
        &self,
        query: &str,
        session_ids: &[Uuid],
        caller_trust: HistoryCallerTrust,
        max_sessions: u32,
        max_rows_per_session: u32,
    ) -> Result<ToolEventScan> {
        let query = query.to_string();
        let session_ids = session_ids.to_vec();
        self.read(move |conn| {
            scan_tool_events_in_sessions_conn(
                conn,
                &query,
                &session_ids,
                caller_trust,
                max_sessions,
                max_rows_per_session,
            )
        })
        .await
    }
}

fn search_candidates_inner(
    conn: &Connection,
    query: &str,
    project_id: Option<&str>,
    exclude_session: Option<Uuid>,
    since: Option<i64>,
    pool: u32,
    caller_trust: HistoryCallerTrust,
    allowed_session_ids: Option<&[Uuid]>,
) -> Result<Vec<SearchHit>> {
    let Some(match_query) = literal_fts_match_query(query) else {
        return Ok(Vec::new());
    };

    let terms = literal_fts_terms(query);

    // Pull every matching FTS row joined through the identifier-only rowid
    // mapping table to the canonical session/event text, ranked by BM25.
    // We over-fetch (rows, not threads) and collapse to one hit per thread
    // in Rust, keeping each thread's best-ranking canonical-text snippet.
    // The SQL filters scope/archive/current/recency up front so the row set
    // stays small.
    let mut stmt = conn
        .prepare(
            "SELECT f.session_id AS session_id,
                    s.short_id    AS short_id,
                    s.title       AS title,
                    s.last_active_at_unix_ms AS last_active_at_unix_ms,
                    CASE f.row_kind
                      WHEN 'title' THEN s.title
                      WHEN 'compaction' THEN COALESCE(
                        json_extract(e.data_json, '$.brief_text'),
                        json_extract(e.data_json, '$.handoff_text'),
                        json_extract(h.payload_json, '$.brief_text'),
                        json_extract(h.payload_json, '$.handoff_text')
                      )
                      ELSE json_extract(e.data_json, '$.text')
                    END AS body,
                    bm25(session_fts) AS rank
               FROM session_fts
               JOIN session_fts_docs AS f ON f.rowid = session_fts.rowid
               JOIN sessions AS s ON s.session_id = f.session_id
          LEFT JOIN session_events AS e ON e.seq = f.seq
          LEFT JOIN compaction_handoffs AS h
                 ON h.handoff_id = json_extract(e.data_json, '$.handoff_ref')
                AND h.session_id = e.session_id
              WHERE session_fts MATCH ?1
                AND s.archived_at_unix_ms IS NULL
                AND (?2 IS NULL OR s.project_id = ?2)
                AND (?3 IS NULL OR s.session_id <> ?3)
                AND (?4 IS NULL OR s.last_active_at_unix_ms >= ?4)
                AND (?5 OR f.row_kind = 'title' OR e.model_trust IS NULL OR e.model_trust <> 'trusted')
                AND (?6 IS NULL OR f.session_id IN (SELECT value FROM json_each(?6)))
              ORDER BY rank ASC, s.last_active_at_unix_ms DESC",
        )
        .context("preparing search_candidates")?;

    let exclude = exclude_session.map(|u| u.to_string());
    let allowed_session_ids = allowed_session_ids.map(|ids| {
        serde_json::to_string(&ids.iter().map(Uuid::to_string).collect::<Vec<_>>())
            .expect("UUID session ids serialize")
    });
    let rows = stmt
        .query_map(
            params![
                match_query,
                project_id,
                exclude,
                since,
                caller_trust.can_read_trusted(),
                allowed_session_ids,
            ],
            |row| {
                let sid: String = row.get("session_id")?;
                Ok((
                    sid,
                    row.get::<_, Option<String>>("short_id")?,
                    row.get::<_, Option<String>>("title")?,
                    row.get::<_, i64>("last_active_at_unix_ms")?,
                    row.get::<_, Option<String>>("body")?,
                    row.get::<_, f64>("rank")?,
                ))
            },
        )
        .context("querying search_candidates")?;

    // Collapse to one hit per thread, keeping the first (best-ranking)
    // snippet seen — the rows arrive in BM25-then-recency order, so the
    // first occurrence of a session is already its strongest hit.
    let mut order: Vec<Uuid> = Vec::new();
    let mut by_session: std::collections::HashMap<Uuid, SearchHit> =
        std::collections::HashMap::new();
    for r in rows {
        let (sid, short_id, title, last_active_at_unix_ms, body, bm25) =
            r.context("decoding search hit")?;
        let session_id = Uuid::parse_str(&sid).with_context(|| format!("session_id `{sid}`"))?;
        if by_session.contains_key(&session_id) {
            continue;
        }
        let Some(body) = body else {
            continue;
        };
        order.push(session_id);
        by_session.insert(
            session_id,
            SearchHit {
                session_id,
                short_id,
                title,
                last_active_at_unix_ms,
                snippet: canonical_snippet(&body, &terms),
                bm25,
            },
        );
        if order.len() as u32 >= pool {
            break;
        }
    }

    Ok(rank_candidates(
        order
            .into_iter()
            .map(|id| by_session.remove(&id).unwrap())
            .collect(),
    ))
}

fn search_candidates_in_sessions_inner(
    conn: &Connection,
    query: &str,
    session_ids: &[Uuid],
    pool: u32,
    caller_trust: HistoryCallerTrust,
) -> Result<Vec<SearchHit>> {
    let Some(match_query) = literal_fts_match_query(query) else {
        return Ok(Vec::new());
    };
    let terms = literal_fts_terms(query);
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for session_id in session_ids {
        let mut stmt = conn
            .prepare(
                "SELECT f.session_id AS session_id,
                        s.short_id AS short_id,
                        s.title AS title,
                        s.last_active_at_unix_ms AS last_active_at_unix_ms,
                        CASE f.row_kind
                          WHEN 'title' THEN s.title
                          WHEN 'compaction' THEN COALESCE(
                            json_extract(e.data_json, '$.brief_text'),
                            json_extract(e.data_json, '$.handoff_text'),
                            json_extract(h.payload_json, '$.brief_text'),
                            json_extract(h.payload_json, '$.handoff_text')
                          )
                          ELSE json_extract(e.data_json, '$.text')
                        END AS body,
                        bm25(session_fts) AS rank
                   FROM session_fts
                   JOIN session_fts_docs AS f ON f.rowid = session_fts.rowid
                   JOIN sessions AS s ON s.session_id = f.session_id
              LEFT JOIN session_events AS e ON e.seq = f.seq
              LEFT JOIN compaction_handoffs AS h
                     ON h.handoff_id = json_extract(e.data_json, '$.handoff_ref')
                    AND h.session_id = e.session_id
                  WHERE session_fts MATCH ?1
                    AND f.session_id = ?2
                    AND (?3 OR f.row_kind = 'title' OR e.model_trust IS NULL OR e.model_trust <> 'trusted')
                  ORDER BY rank ASC, f.seq ASC",
            )
            .context("preparing lineage search")?;
        let rows = stmt
            .query_map(
                params![
                    match_query,
                    session_id.to_string(),
                    caller_trust.can_read_trusted()
                ],
                |row| {
                    let sid: String = row.get("session_id")?;
                    Ok((
                        sid,
                        row.get::<_, Option<String>>("short_id")?,
                        row.get::<_, Option<String>>("title")?,
                        row.get::<_, i64>("last_active_at_unix_ms")?,
                        row.get::<_, Option<String>>("body")?,
                        row.get::<_, f64>("rank")?,
                    ))
                },
            )
            .context("querying lineage search")?;
        for row in rows {
            let (sid, short_id, title, last_active_at_unix_ms, body, bm25) =
                row.context("decoding lineage search hit")?;
            let hit_session_id =
                Uuid::parse_str(&sid).with_context(|| format!("session_id `{sid}`"))?;
            if !seen.insert(hit_session_id) {
                continue;
            }
            let Some(body) = body else {
                continue;
            };
            out.push(SearchHit {
                session_id: hit_session_id,
                short_id,
                title,
                last_active_at_unix_ms,
                snippet: canonical_snippet(&body, &terms),
                bm25,
            });
            if out.len() as u32 >= pool {
                return Ok(rank_candidates(out));
            }
        }
    }
    Ok(rank_candidates(out))
}

fn compaction_lineage_sessions_conn(conn: &Connection, session_id: Uuid) -> Result<Vec<Uuid>> {
    let existing = existing_session_ids(conn)?;
    if !existing.contains(&session_id) {
        return Ok(Vec::new());
    }
    let links = compaction_links(conn)?;
    let mut visited = std::collections::HashSet::new();
    visited.insert(session_id);

    let mut backwards = Vec::new();
    let mut cursor = session_id;
    while let Some((predecessor, _)) = links.iter().find(|(_, successor)| *successor == cursor) {
        if !existing.contains(predecessor) || !visited.insert(*predecessor) {
            break;
        }
        backwards.push(*predecessor);
        cursor = *predecessor;
    }
    backwards.reverse();

    let mut forwards = Vec::new();
    cursor = session_id;
    while let Some((_, successor)) = links.iter().find(|(predecessor, _)| *predecessor == cursor) {
        if !existing.contains(successor) || !visited.insert(*successor) {
            break;
        }
        forwards.push(*successor);
        cursor = *successor;
    }

    let mut lineage = backwards;
    lineage.push(session_id);
    lineage.extend(forwards);
    Ok(lineage)
}

fn existing_session_ids(conn: &Connection) -> Result<std::collections::HashSet<Uuid>> {
    let mut stmt = conn
        .prepare("SELECT session_id FROM sessions")
        .context("preparing session id scan")?;
    let rows = stmt
        .query_map([], |row| row.get::<_, String>("session_id"))
        .context("querying session ids")?;
    let mut out = std::collections::HashSet::new();
    for row in rows {
        let sid = row.context("decoding session id")?;
        out.insert(Uuid::parse_str(&sid).with_context(|| format!("session_id `{sid}`"))?);
    }
    Ok(out)
}

fn compaction_links(conn: &Connection) -> Result<Vec<(Uuid, Uuid)>> {
    let mut stmt = conn
        .prepare(
            "SELECT e.session_id, e.data_json, h.payload_json
               FROM session_events e
          LEFT JOIN compaction_handoffs h
                 ON h.handoff_id = json_extract(e.data_json, '$.handoff_ref')
                AND h.session_id = e.session_id
              WHERE e.type = 'session_compacted'
              ORDER BY e.seq ASC",
        )
        .context("preparing compaction link scan")?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>("session_id")?,
                row.get::<_, String>("data_json")?,
                row.get::<_, Option<String>>("payload_json")?,
            ))
        })
        .context("querying compaction links")?;
    let mut out = Vec::new();
    for row in rows {
        let (_, data_json, payload_json) = row.context("decoding compaction link")?;
        let link_source = payload_json.as_deref().unwrap_or(data_json.as_str());
        let Ok(value) = serde_json::from_str::<Value>(link_source) else {
            continue;
        };
        let Some(predecessor) = value
            .get("predecessor_session_id")
            .and_then(Value::as_str)
            .and_then(|id| Uuid::parse_str(id).ok())
        else {
            continue;
        };
        let Some(successor) = value
            .get("successor_session_id")
            .and_then(Value::as_str)
            .and_then(|id| Uuid::parse_str(id).ok())
        else {
            continue;
        };
        out.push((predecessor, successor));
    }
    Ok(out)
}

fn scan_tool_events_in_sessions_conn(
    conn: &Connection,
    query: &str,
    session_ids: &[Uuid],
    caller_trust: HistoryCallerTrust,
    max_sessions: u32,
    max_rows_per_session: u32,
) -> Result<ToolEventScan> {
    let terms = literal_fts_terms(query);
    if terms.is_empty() {
        return Ok(ToolEventScan {
            hits: Vec::new(),
            truncated: false,
        });
    }
    let needle = terms.join(" ");
    let mut hits = Vec::new();
    let mut truncated = session_ids.len() > max_sessions as usize;
    for session_id in session_ids.iter().take(max_sessions as usize) {
        let fetch_limit = i64::from(max_rows_per_session.clamp(1, 100)) + 1;
        let mut stmt = conn
            .prepare(
                "SELECT seq, type, data_json
                   FROM session_events
                  WHERE session_id = ?1
                    AND type IN ('tool_call', 'tool_call_started', 'tool_call_completed', 'tool_rejected')
                    AND instr(lower(data_json), lower(?2)) > 0
                    AND (?3 OR model_trust IS NULL OR model_trust <> 'trusted')
                  ORDER BY seq ASC
                  LIMIT ?4",
            )
            .context("preparing bounded tool event scan")?;
        let rows = stmt
            .query_map(
                params![
                    session_id.to_string(),
                    needle,
                    caller_trust.can_read_trusted(),
                    fetch_limit
                ],
                |row| {
                    Ok((
                        row.get::<_, i64>("seq")?,
                        row.get::<_, String>("type")?,
                        row.get::<_, String>("data_json")?,
                    ))
                },
            )
            .context("querying bounded tool event scan")?;
        for (idx, row) in rows.enumerate() {
            if idx >= max_rows_per_session as usize {
                truncated = true;
                break;
            }
            let (seq, event_type, data_json) = row.context("decoding tool event scan hit")?;
            hits.push(ToolEventScanHit {
                session_id: *session_id,
                seq,
                event_type,
                snippet: canonical_snippet(&data_json, &terms),
            });
        }
    }
    Ok(ToolEventScan { hits, truncated })
}

const SNIPPET_CONTEXT_CHARS: usize = 48;
const SNIPPET_FALLBACK_CHARS: usize = 120;

pub(crate) fn literal_fts_terms(query: &str) -> Vec<String> {
    query
        .split(|ch: char| !ch.is_alphanumeric())
        .filter(|term| !term.is_empty())
        .map(str::to_lowercase)
        .collect()
}

pub(crate) fn canonical_snippet(text: &str, terms: &[String]) -> String {
    let Some((start, end)) = first_literal_match(text, terms) else {
        return bounded_excerpt(text, 0, SNIPPET_FALLBACK_CHARS);
    };
    let excerpt_start = retreat_chars(text, start, SNIPPET_CONTEXT_CHARS);
    let excerpt_end = advance_chars(text, end, SNIPPET_CONTEXT_CHARS);
    let mut out = String::new();
    if excerpt_start > 0 {
        out.push('…');
    }
    out.push_str(&text[excerpt_start..start]);
    out.push('[');
    out.push_str(&text[start..end]);
    out.push(']');
    out.push_str(&text[end..excerpt_end]);
    if excerpt_end < text.len() {
        out.push('…');
    }
    out
}

fn first_literal_match(text: &str, terms: &[String]) -> Option<(usize, usize)> {
    let mut best: Option<(usize, usize)> = None;
    for (idx, _) in text.char_indices() {
        let tail = &text[idx..];
        for term in terms {
            if term.is_empty() {
                continue;
            }
            let mut tail_chars = tail.chars();
            let mut matched_end = idx;
            let mut ok = true;
            for expected in term.chars() {
                let Some(actual) = tail_chars.next() else {
                    ok = false;
                    break;
                };
                if !actual.to_lowercase().eq(expected.to_lowercase()) {
                    ok = false;
                    break;
                }
                matched_end += actual.len_utf8();
            }
            if ok && best.is_none_or(|(best_start, _)| idx < best_start) {
                best = Some((idx, matched_end));
            }
        }
    }
    best
}

fn bounded_excerpt(text: &str, start: usize, max_chars: usize) -> String {
    let end = advance_chars(text, start, max_chars);
    let mut out = String::new();
    out.push_str(&text[start..end]);
    if end < text.len() {
        out.push('…');
    }
    out
}

fn retreat_chars(text: &str, end: usize, count: usize) -> usize {
    text[..end]
        .char_indices()
        .rev()
        .nth(count.saturating_sub(1))
        .map_or(0, |(idx, _)| idx)
}

fn advance_chars(text: &str, start: usize, count: usize) -> usize {
    if count == 0 {
        return start;
    }
    text[start..]
        .char_indices()
        .nth(count)
        .map_or(text.len(), |(idx, _)| start + idx)
}

fn literal_fts_match_query(query: &str) -> Option<String> {
    let terms = literal_fts_terms(query);
    if terms.is_empty() {
        return None;
    }
    Some(
        terms
            .into_iter()
            .map(|term| format!("\"{}\"", term.replace('"', "\"\"")))
            .collect::<Vec<_>>()
            .join(" OR "),
    )
}

/// Final ranking pass over the FTS candidate pool. **Seam for a future
/// embedding re-ranker** (prompt: "leave a clean seam where a future
/// embedding ranker could re-rank FTS candidates"). Today the score is
/// the raw FTS5 BM25 relevance (`hit.bm25`, lower = better), so this is
/// the SQL order made explicit; a re-ranker swaps the key for a blended
/// semantic score without touching either tool's schema or the DB query
/// surface. The sort is stable, so the SQL `last_active_at_unix_ms` recency
/// tiebreaker survives ties.
fn rank_candidates(mut candidates: Vec<SearchHit>) -> Vec<SearchHit> {
    candidates.sort_by(|a, b| {
        a.bm25
            .partial_cmp(&b.bm25)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    candidates
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::session_log::{SessionEventContext, SessionEventKind};
    use rusqlite::params;
    use serde_json::json;

    /// Insert a message event and return its seq.
    async fn msg(db: &Db, session_id: Uuid, kind: SessionEventKind, text: &str) -> i64 {
        db.insert_session_event(session_id, kind, None, None, &json!({ "text": text }))
            .await
            .unwrap()
    }

    async fn event_with_trust(
        db: &Db,
        session_id: Uuid,
        kind: SessionEventKind,
        text: &str,
        trust: Option<&str>,
    ) -> i64 {
        db.insert_session_event_with_context(
            session_id,
            kind,
            None,
            None,
            SessionEventContext {
                model_trust: trust,
                provider_id: trust.map(|_| "provider-a"),
                model_id: trust.map(|_| "model-a"),
                ..Default::default()
            },
            &json!({ "text": text }),
        )
        .await
        .unwrap()
    }

    async fn compact_link(
        db: &Db,
        predecessor: Uuid,
        successor: Uuid,
        body: &str,
        spilled: bool,
    ) -> i64 {
        let payload = json!({
            "kind": "compaction",
            "predecessor_session_id": predecessor.to_string(),
            "successor_session_id": successor.to_string(),
            "brief_text": body,
            "handoff_text": format!("handoff {body}"),
        });
        let data = if spilled {
            let handoff_id = Uuid::new_v4();
            db.store_compaction_payload(handoff_id, predecessor, &payload.to_string())
                .await
                .unwrap();
            json!({
                "kind": "compaction",
                "predecessor_session_id": predecessor.to_string(),
                "successor_session_id": successor.to_string(),
                "handoff_ref": handoff_id.to_string(),
            })
        } else {
            payload
        };
        db.insert_session_event_with_context(
            predecessor,
            SessionEventKind::SessionCompacted,
            Some("Build"),
            None,
            SessionEventContext {
                provider_id: Some("provider-a"),
                model_id: Some("model-a"),
                model_trust: Some("untrusted"),
                ..Default::default()
            },
            &data,
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn history_trust_filters_search_and_thread_reads_in_sql() {
        let db = Db::open_in_memory().unwrap();
        let all_trusted = db.create_session("p", "/a", "Build").await.unwrap();
        let mixed = db.create_session("p", "/b", "Build").await.unwrap();

        event_with_trust(
            &db,
            all_trusted.session_id,
            SessionEventKind::AssistantMessage,
            "needle only trusted",
            Some("trusted"),
        )
        .await;
        event_with_trust(
            &db,
            mixed.session_id,
            SessionEventKind::AssistantMessage,
            "needle trusted hidden",
            Some("trusted"),
        )
        .await;
        event_with_trust(
            &db,
            mixed.session_id,
            SessionEventKind::AssistantMessage,
            "needle untrusted visible",
            Some("untrusted"),
        )
        .await;
        event_with_trust(
            &db,
            mixed.session_id,
            SessionEventKind::UserMessage,
            "needle null visible",
            None,
        )
        .await;

        let untrusted = db
            .search_candidates_for_trust(
                "needle",
                Some("p"),
                None,
                None,
                10,
                HistoryCallerTrust::Untrusted,
            )
            .await
            .unwrap();
        assert_eq!(
            untrusted
                .iter()
                .map(|hit| hit.session_id)
                .collect::<Vec<_>>(),
            vec![mixed.session_id]
        );

        let trusted = db
            .search_candidates_for_trust(
                "needle",
                Some("p"),
                None,
                None,
                10,
                HistoryCallerTrust::Trusted,
            )
            .await
            .unwrap();
        assert_eq!(trusted.len(), 2);

        let turns = db
            .thread_turns_for_trust(mixed.session_id, HistoryCallerTrust::Untrusted)
            .await
            .unwrap();
        assert_eq!(turns.len(), 2);
        assert!(
            turns
                .iter()
                .all(|turn| !turn.text.contains("trusted hidden"))
        );
    }

    #[tokio::test]
    async fn history_trust_lineage_walks_spilled_links_and_stops_on_cycles() {
        let db = Db::open_in_memory().unwrap();
        let a = db.create_session("p", "/a", "Build").await.unwrap();
        let b = db.create_session("p", "/b", "Build").await.unwrap();
        let c = db.create_session("p", "/c", "Build").await.unwrap();
        compact_link(&db, a.session_id, b.session_id, "alpha-brief", false).await;
        compact_link(&db, b.session_id, c.session_id, "bravo-brief", true).await;

        let lineage = db.compaction_lineage_sessions(b.session_id).await.unwrap();
        assert_eq!(lineage, vec![a.session_id, b.session_id, c.session_id]);

        compact_link(&db, c.session_id, a.session_id, "cycle-brief", false).await;
        let cyclic = db.compaction_lineage_sessions(a.session_id).await.unwrap();
        assert!(cyclic.len() <= 3, "cycle must not loop: {cyclic:?}");
        assert!(cyclic.contains(&a.session_id));

        let dangling = db.create_session("p", "/dangling", "Build").await.unwrap();
        compact_link(
            &db,
            dangling.session_id,
            Uuid::new_v4(),
            "dangling-brief",
            false,
        )
        .await;
        assert_eq!(
            db.compaction_lineage_sessions(dangling.session_id)
                .await
                .unwrap(),
            vec![dangling.session_id]
        );
    }

    #[tokio::test]
    async fn history_trust_fts_indexes_compaction_briefs_inline_and_spilled() {
        let db = Db::open_in_memory().unwrap();
        let a = db.create_session("p", "/a", "Build").await.unwrap();
        let b = db.create_session("p", "/b", "Build").await.unwrap();
        let c = db.create_session("p", "/c", "Build").await.unwrap();
        let inline_seq = compact_link(&db, a.session_id, b.session_id, "inlinequartz", false).await;
        compact_link(&db, b.session_id, c.session_id, "spilledtopaz", true).await;

        let inline = db
            .search_candidates("inlinequartz", Some("p"), None, None, 10)
            .await
            .unwrap();
        assert_eq!(inline[0].session_id, a.session_id);
        let spilled = db
            .search_candidates("spilledtopaz", Some("p"), None, None, 10)
            .await
            .unwrap();
        assert_eq!(spilled[0].session_id, b.session_id);

        db.write(move |conn| {
            conn.execute(
                "DELETE FROM session_events WHERE seq = ?1",
                params![inline_seq],
            )?;
            Ok(())
        })
        .await
        .unwrap();
        assert!(
            db.search_candidates("inlinequartz", Some("p"), None, None, 10)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn history_trust_tool_events_are_bounded_scanned_not_indexed_and_trust_filtered() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/a", "Build").await.unwrap();
        db.insert_session_event_with_context(
            session.session_id,
            SessionEventKind::ToolCall,
            Some("Build"),
            Some("call-1"),
            SessionEventContext {
                model_trust: Some("trusted"),
                provider_id: Some("provider-a"),
                model_id: Some("trusted-model"),
                ..Default::default()
            },
            &json!({"tool": "bash", "output": "secretamber trusted"}),
        )
        .await
        .unwrap();
        db.insert_session_event_with_context(
            session.session_id,
            SessionEventKind::ToolCall,
            Some("Build"),
            Some("call-2"),
            SessionEventContext {
                model_trust: Some("untrusted"),
                provider_id: Some("provider-a"),
                model_id: Some("untrusted-model"),
                ..Default::default()
            },
            &json!({"tool": "bash", "output": "secretamber visible"}),
        )
        .await
        .unwrap();

        assert!(
            db.search_candidates("secretamber", Some("p"), None, None, 10)
                .await
                .unwrap()
                .is_empty()
        );
        let scan = db
            .scan_tool_events_in_sessions(
                "secretamber",
                &[session.session_id],
                HistoryCallerTrust::Untrusted,
                1,
                1,
            )
            .await
            .unwrap();
        assert_eq!(scan.hits.len(), 1);
        assert!(scan.hits[0].snippet.contains("visible"));
        assert!(!scan.hits[0].snippet.contains("secretamber trusted"));
        assert!(!scan.truncated);
    }

    #[tokio::test]
    async fn fts5_is_available_in_bundled_build() {
        let db = Db::open_in_memory().unwrap();
        db.fts5_available()
            .await
            .expect("bundled rusqlite must ship FTS5");
    }

    #[tokio::test]
    async fn search_ranks_and_scopes_by_project() {
        let db = Db::open_in_memory().unwrap();
        let a = db.create_session("projA", "/a", "Build").await.unwrap();
        let b = db.create_session("projB", "/b", "Build").await.unwrap();
        msg(
            &db,
            a.session_id,
            SessionEventKind::UserMessage,
            "let us discuss widget calibration",
        )
        .await;
        msg(
            &db,
            b.session_id,
            SessionEventKind::UserMessage,
            "totally unrelated gardening notes",
        )
        .await;

        // Default scope = projA only.
        let hits = db
            .search_candidates("widget", Some("projA"), None, None, 10)
            .await
            .unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].session_id, a.session_id);
        assert!(
            hits[0].snippet.contains('['),
            "snippet must highlight: {}",
            hits[0].snippet
        );

        // projB has no widget match.
        let none = db
            .search_candidates("widget", Some("projB"), None, None, 10)
            .await
            .unwrap();
        assert!(none.is_empty());

        // Global recall still finds it.
        let global = db
            .search_candidates("widget", None, None, None, 10)
            .await
            .unwrap();
        assert_eq!(global.len(), 1);
    }

    #[tokio::test]
    async fn explicit_session_scope_filters_before_candidate_pool_truncation() {
        let db = Db::open_in_memory().unwrap();
        let attached = db
            .create_session("attached", "/attached", "Build")
            .await
            .unwrap();
        msg(
            &db,
            attached.session_id,
            SessionEventKind::UserMessage,
            "shared dream-search marker",
        )
        .await;
        for project in ["unattached-a", "unattached-b", "unattached-c"] {
            let session = db.create_session(project, "/other", "Build").await.unwrap();
            msg(
                &db,
                session.session_id,
                SessionEventKind::UserMessage,
                "shared dream-search marker",
            )
            .await;
        }

        // A global pool of one can be consumed by a later, unattached match.
        // The explicit attachment filter must run in SQL before that pool is
        // ranked and truncated.
        let hits = db
            .search_candidates_in_sessions_for_trust(
                "shared dream-search marker",
                &[attached.session_id],
                None,
                None,
                1,
                HistoryCallerTrust::Trusted,
            )
            .await
            .unwrap();
        assert_eq!(
            hits.iter().map(|hit| hit.session_id).collect::<Vec<_>>(),
            vec![attached.session_id]
        );
    }

    #[tokio::test]
    async fn search_excludes_archived_and_current_session() {
        let db = Db::open_in_memory().unwrap();
        let live = db.create_session("p", "/x", "Build").await.unwrap();
        let archived = db.create_session("p", "/x", "Build").await.unwrap();
        let current = db.create_session("p", "/x", "Build").await.unwrap();
        for s in [&live, &archived, &current] {
            msg(
                &db,
                s.session_id,
                SessionEventKind::UserMessage,
                "shared keyword apricot",
            )
            .await;
        }
        db.archive_session(archived.session_id, false)
            .await
            .unwrap();

        let hits = db
            .search_candidates("apricot", Some("p"), Some(current.session_id), None, 10)
            .await
            .unwrap();
        let ids: Vec<Uuid> = hits.iter().map(|h| h.session_id).collect();
        assert!(ids.contains(&live.session_id));
        assert!(
            !ids.contains(&archived.session_id),
            "archived must be excluded"
        );
        assert!(
            !ids.contains(&current.session_id),
            "current must be excluded"
        );
    }

    #[tokio::test]
    async fn search_indexes_titles() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "Build").await.unwrap();
        db.set_auto_title(s.session_id, "refactor the lock manager")
            .await
            .unwrap();
        let hits = db
            .search_candidates("refactor", Some("p"), None, None, 10)
            .await
            .unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].session_id, s.session_id);
    }

    #[tokio::test]
    async fn search_honors_since_filter() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "Build").await.unwrap();
        msg(
            &db,
            s.session_id,
            SessionEventKind::UserMessage,
            "banana split recipe",
        )
        .await;
        let active = db
            .get_session(s.session_id)
            .await
            .unwrap()
            .unwrap()
            .last_active_at_unix_ms;
        // since in the future → filtered out.
        let later = db
            .search_candidates("banana", Some("p"), None, Some(active + 10_000), 10)
            .await
            .unwrap();
        assert!(later.is_empty());
        // since in the past → included.
        let earlier = db
            .search_candidates("banana", Some("p"), None, Some(active - 10_000), 10)
            .await
            .unwrap();
        assert_eq!(earlier.len(), 1);
    }

    #[tokio::test]
    async fn no_match_is_empty_not_error() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "Build").await.unwrap();
        msg(
            &db,
            s.session_id,
            SessionEventKind::UserMessage,
            "hello world",
        )
        .await;
        let hits = db
            .search_candidates("nonexistentterm", Some("p"), None, None, 10)
            .await
            .unwrap();
        assert!(hits.is_empty());
    }

    #[tokio::test]
    async fn literal_fts_query_tokenizes_malformed_syntax_safely() {
        assert_eq!(
            literal_fts_match_query(r#"foo "bar baz" ("#).as_deref(),
            Some(r#""foo" OR "bar" OR "baz""#)
        );
        assert_eq!(
            literal_fts_match_query("foo OR bar").as_deref(),
            Some(r#""foo" OR "or" OR "bar""#)
        );
        assert_eq!(literal_fts_match_query(" ()!? ").as_deref(), None);
        assert_eq!(literal_fts_match_query("").as_deref(), None);
    }

    #[tokio::test]
    async fn malformed_search_candidates_queries_never_surface_fts_syntax_errors() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "Build").await.unwrap();
        msg(
            &db,
            s.session_id,
            SessionEventKind::UserMessage,
            "foo bar phrase with a quoted token",
        )
        .await;

        for query in [r#""foo"#, "foo)", "(bar", "foo OR bar"] {
            let hits = db
                .search_candidates(query, Some("p"), None, None, 10)
                .await
                .unwrap();
            assert_eq!(hits.len(), 1, "query {query:?}");
            assert_eq!(hits[0].session_id, s.session_id);
        }

        for query in ["", "   ", "?!()"] {
            let hits = db
                .search_candidates(query, Some("p"), None, None, 10)
                .await
                .unwrap();
            assert!(hits.is_empty(), "query {query:?}");
        }
    }

    #[tokio::test]
    async fn malformed_thread_match_queries_never_surface_fts_syntax_errors() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "Build").await.unwrap();
        let seq = msg(
            &db,
            s.session_id,
            SessionEventKind::UserMessage,
            "embedded quote syntax and falcon topic",
        )
        .await;

        for query in [r#""falcon"#, "falcon)", "(syntax", "falcon OR syntax"] {
            let seqs = db.thread_match_seqs(s.session_id, query).await.unwrap();
            assert!(seqs.contains(&seq), "query {query:?}: {seqs:?}");
        }

        for query in ["", "   ", "?!()"] {
            assert!(
                db.thread_match_seqs(s.session_id, query)
                    .await
                    .unwrap()
                    .is_empty(),
                "query {query:?}"
            );
        }
    }

    #[tokio::test]
    async fn ordinary_multi_word_search_still_finds_and_highlights() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "Build").await.unwrap();
        msg(
            &db,
            s.session_id,
            SessionEventKind::AssistantMessage,
            "alpha beta gamma migration",
        )
        .await;
        let hits = db
            .search_candidates("alpha beta", Some("p"), None, None, 10)
            .await
            .unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].session_id, s.session_id);
        assert!(
            hits[0].snippet.contains("[alpha]") || hits[0].snippet.contains("[beta]"),
            "snippet: {}",
            hits[0].snippet
        );
    }

    #[tokio::test]
    async fn session_fts_is_contentless_and_does_not_expose_body_text() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "Build").await.unwrap();
        let secret = "secret_like_indexed_value_123";
        msg(&db, s.session_id, SessionEventKind::UserMessage, secret).await;

        db.read(move |conn| {
            let ddl: String = conn.query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'session_fts'",
                [],
                |row| row.get(0),
            )?;
            assert!(ddl.contains("content=''"), "ddl: {ddl}");

            let body: Option<String> = conn.query_row(
                "SELECT body FROM session_fts WHERE session_fts MATCH ?1 LIMIT 1",
                [secret],
                |row| row.get(0),
            )?;
            assert!(body.is_none(), "contentless FTS must not return body text");

            let canonical: String = conn.query_row(
                "SELECT json_extract(data_json, '$.text')
                   FROM session_events
                  WHERE session_id = ?1",
                [s.session_id.to_string()],
                |row| row.get(0),
            )?;
            assert_eq!(canonical, secret);
            Ok(())
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn canonical_snippet_highlights_terms_and_handles_utf8_boundaries() {
        let terms = literal_fts_terms("beta!");
        assert_eq!(
            canonical_snippet("alpha beta gamma", &terms),
            "alpha [beta] gamma"
        );

        let terms = literal_fts_terms("resume");
        assert_eq!(
            canonical_snippet("emoji 😀 resume cafe", &terms),
            "emoji 😀 [resume] cafe"
        );

        let terms = literal_fts_terms("missing");
        let snippet = canonical_snippet("😀é中abc", &terms);
        assert_eq!(snippet, "😀é中abc");
    }

    #[tokio::test]
    async fn title_update_event_update_and_deletes_keep_fts_in_sync() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "Build").await.unwrap();
        db.set_auto_title(s.session_id, "original dashboard")
            .await
            .unwrap();
        let seq = msg(
            &db,
            s.session_id,
            SessionEventKind::UserMessage,
            "original body keyword",
        )
        .await;

        db.set_auto_title(s.session_id, "renamed dashboard")
            .await
            .unwrap();
        assert!(
            db.search_candidates("original", Some("p"), None, None, 10)
                .await
                .unwrap()
                .iter()
                .any(|hit| hit.session_id == s.session_id),
            "message still contains original"
        );
        assert_eq!(
            db.search_candidates("renamed", Some("p"), None, None, 10)
                .await
                .unwrap()
                .len(),
            1
        );

        db.write(move |conn| {
            conn.execute(
                "UPDATE session_events
                    SET data_json = json_object('text', 'updated body keyword')
                  WHERE seq = ?1",
                [seq],
            )?;
            Ok(())
        })
        .await
        .unwrap();
        assert!(
            db.search_candidates("original", Some("p"), None, None, 10)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            db.search_candidates("updated", Some("p"), None, None, 10)
                .await
                .unwrap()
                .len(),
            1
        );

        db.write(move |conn| {
            conn.execute("DELETE FROM session_events WHERE seq = ?1", [seq])?;
            Ok(())
        })
        .await
        .unwrap();
        assert!(
            db.search_candidates("updated", Some("p"), None, None, 10)
                .await
                .unwrap()
                .is_empty()
        );

        db.write(move |conn| {
            conn.execute(
                "DELETE FROM sessions WHERE session_id = ?1",
                [s.session_id.to_string()],
            )?;
            Ok(())
        })
        .await
        .unwrap();
        assert!(
            db.search_candidates("renamed", Some("p"), None, None, 10)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn backfill_indexes_preexisting_rows() {
        // Simulate pre-migration data: insert events with the FTS triggers
        // dropped, then re-run the backfill statements and confirm the
        // rows become searchable. We mimic this by inserting directly with
        // triggers in place (the live path) AND verifying a row inserted
        // before any search is found — the migration's backfill is what
        // makes Db::open_in_memory()'s already-applied schema index the
        // create_session title path; message backfill is covered by the
        // trigger path. To exercise the literal backfill SQL, insert an
        // event row by hand bypassing nothing (triggers fire) — then drop
        // and rebuild the FTS table from the backfill statements.
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "Build").await.unwrap();
        msg(
            &db,
            s.session_id,
            SessionEventKind::AssistantMessage,
            "the quokka is a marsupial",
        )
        .await;

        // Drop the FTS contents and re-run the backfill to prove the
        // backfill SQL (not just the triggers) reconstructs the index.
        db.write(move |conn| {
            conn.execute_batch(
                "INSERT INTO session_fts(session_fts) VALUES('delete-all');
                 DELETE FROM session_fts_docs;",
            )?;
            conn.execute_batch(
                "INSERT INTO session_fts_docs (row_kind, session_id, seq)
                 SELECT 'message', session_id, seq
                 FROM session_events
                 WHERE type IN ('user_message','assistant_message')
                   AND json_extract(data_json, '$.text') IS NOT NULL;
                 INSERT INTO session_fts (rowid, body)
                 SELECT d.rowid, json_extract(e.data_json, '$.text')
                 FROM session_fts_docs AS d
                 JOIN session_events AS e ON e.seq = d.seq
                 WHERE d.row_kind = 'message';",
            )?;
            Ok(())
        })
        .await
        .unwrap();

        let hits = db
            .search_candidates("quokka", Some("p"), None, None, 10)
            .await
            .unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].session_id, s.session_id);
    }

    #[tokio::test]
    async fn thread_turns_and_match_seqs() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "Build").await.unwrap();
        let s1 = msg(
            &db,
            s.session_id,
            SessionEventKind::UserMessage,
            "what is a kestrel",
        )
        .await;
        let _s2 = msg(
            &db,
            s.session_id,
            SessionEventKind::AssistantMessage,
            "a small falcon",
        )
        .await;
        let s3 = msg(
            &db,
            s.session_id,
            SessionEventKind::UserMessage,
            "and the kestrel diet",
        )
        .await;

        let turns = db.thread_turns(s.session_id).await.unwrap();
        assert_eq!(turns.len(), 3);
        assert_eq!(turns[0].role, "user");
        assert_eq!(turns[1].role, "assistant");

        let seqs = db.thread_match_seqs(s.session_id, "kestrel").await.unwrap();
        assert_eq!(seqs, vec![s1, s3]);
    }
}
