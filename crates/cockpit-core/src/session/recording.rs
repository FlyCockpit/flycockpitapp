use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelSwitchTrigger {
    Picker,
    Quick,
    Cycle,
    Daemon,
}

impl ModelSwitchTrigger {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Picker => "picker",
            Self::Quick => "quick",
            Self::Cycle => "cycle",
            Self::Daemon => "daemon",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelSwitchOutcome {
    Ok,
    BuildFailed,
    SendFailed,
    Noop,
}

impl ModelSwitchOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::BuildFailed => "build_failed",
            Self::SendFailed => "send_failed",
            Self::Noop => "noop",
        }
    }
}

#[derive(Debug, Clone)]
struct SessionEventProvenance {
    provider_id: String,
    model_id: String,
    llm_mode: crate::config::extended::LlmMode,
    model_trust: crate::config::providers::ModelTrust,
}

#[derive(Clone, Copy)]
pub struct SessionEventModelFrame<'a> {
    pub provider_id: &'a str,
    pub model_id: &'a str,
    pub config: &'a crate::daemon::session_worker::SessionConfigHandle,
    /// Pre-policy session redaction table for the model authoring this event.
    /// Used only to journal the event's table-matched literals when the target
    /// is trusted (decision 10.3); never the trusted-empty effective table.
    pub session_table: &'a crate::redact::RedactionTable,
}

impl SessionEventModelFrame<'_> {
    /// The trust class this frame's AUTHORING `(provider, model)` resolves to
    /// under the frame's pinned config snapshot. This is the SINGLE source of
    /// truth for the journal-vs-scrub decision: the model-authored session event
    /// resolves its trust from exactly this expression (see
    /// [`Session::session_event_provenance_for`], which reads
    /// `frame.config.snapshot().providers.resolve_trust(frame.provider_id,
    /// frame.model_id)`), so a co-persisted `tool_call_events` audit row that
    /// derives `target_trusted` from THIS method can never disagree with its
    /// session event — both journal, or both scrub — regardless of which model
    /// the session's PRIMARY happens to be (a primary→failover author is
    /// classified by the authoring frame, not the after-turn primary).
    pub fn resolved_model_trust(&self) -> crate::config::providers::ModelTrust {
        self.config
            .snapshot()
            .providers
            .resolve_trust(self.provider_id, self.model_id)
    }

    /// `true` iff [`Self::resolved_model_trust`] is trusted.
    pub fn resolved_trusted(&self) -> bool {
        matches!(
            self.resolved_model_trust(),
            crate::config::providers::ModelTrust::Trusted
        )
    }
}

impl SessionEventProvenance {
    fn context_fields(&self) -> (&str, &str, &str, &str) {
        (
            self.provider_id.as_str(),
            self.model_id.as_str(),
            self.llm_mode.as_str(),
            model_trust_as_str(self.model_trust),
        )
    }
}

fn model_trust_as_str(trust: crate::config::providers::ModelTrust) -> &'static str {
    match trust {
        crate::config::providers::ModelTrust::Trusted => "trusted",
        crate::config::providers::ModelTrust::Untrusted => "untrusted",
    }
}

fn event_kind_is_model_authored(kind: crate::db::session_log::SessionEventKind) -> bool {
    use crate::db::session_log::SessionEventKind;
    matches!(
        kind,
        SessionEventKind::AssistantMessage
            | SessionEventKind::InferenceRequest
            | SessionEventKind::ToolCall
            | SessionEventKind::ToolCallStarted
            | SessionEventKind::ToolCallCompleted
            | SessionEventKind::SubagentSpawned
            | SessionEventKind::SubagentRouting
            | SessionEventKind::SubagentReport
            | SessionEventKind::SessionCompacted
            | SessionEventKind::ToolRejected
            | SessionEventKind::PrimarySwap
            | SessionEventKind::InferenceFailure
            | SessionEventKind::FailedTurnRecovery
            | SessionEventKind::SkillAutoSelect
            | SessionEventKind::AutoPruneDiagnostic
            | SessionEventKind::GoalProgressDiagnostic
    )
}

/// Map one [`crate::redact::MatchedLiteral`] to a [`ProtectedLiteral`] ready for
/// `prepare_append`, carrying its typed source and (for sealed entries) the
/// record id / version read directly from the typed identity — never parsed from
/// a display string.
fn matched_to_protected_literal(
    m: &crate::redact::MatchedLiteral,
) -> Result<crate::redact::protected_redaction_history::ProtectedLiteral> {
    use crate::redact::SourceClass;
    use crate::redact::protected_redaction_history::{ProtectedLiteral, RedactionHistorySource};
    let (source, sealed_record_id, sealed_version) = match &m.source {
        SourceClass::Environment => (RedactionHistorySource::Environment, None, None),
        SourceClass::Credential => (RedactionHistorySource::Credential, None, None),
        SourceClass::ContainedLeak => (RedactionHistorySource::ContainedLeak, None, None),
        SourceClass::Sealed { record_id, version } => (
            RedactionHistorySource::Sealed,
            record_id.as_ref().map(|id| id.to_string()),
            Some(i64::from(*version)),
        ),
    };
    ProtectedLiteral::new(m.literal.clone(), source, sealed_record_id, sealed_version)
}

/// Walk a parsed JSON value and return the DISTINCT redaction-table literals that
/// occur in any DECODED string leaf (object value, array element), object KEY, or
/// the canonical text of a non-string scalar leaf (a number/bool — e.g. a numeric
/// PIN literal in `{"pin":1234}`, which a string-only walk would miss; G4b). A
/// `null` is skipped. Scalar matching is table-match-only, so an ordinary number
/// absent from the table never matches.
///
/// Matching the decoded string values — not the serialized blob — is what makes
/// this JSON-escape-safe (F2): a literal containing JSON-special characters
/// (`"`, `\`, or control/unicode escapes) is stored verbatim in the table but is
/// ESCAPED in the serialized wire form, so an Aho-Corasick scan of the serialized
/// string would never find `a"b` (it appears there as `a\"b`). Scanning each
/// decoded value instead sees the literal exactly as the table registered it.
/// Distinct by literal across the whole tree so each table entry journals once.
fn match_literals_in_json(
    table: &crate::redact::RedactionTable,
    value: &Value,
) -> Vec<crate::redact::MatchedLiteral> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    collect_json_matches(table, value, &mut seen, &mut out);
    out
}

fn collect_json_matches(
    table: &crate::redact::RedactionTable,
    value: &Value,
    seen: &mut std::collections::HashSet<String>,
    out: &mut Vec<crate::redact::MatchedLiteral>,
) {
    match value {
        Value::String(s) => push_string_matches(table, s, seen, out),
        Value::Array(items) => {
            for item in items {
                collect_json_matches(table, item, seen, out);
            }
        }
        Value::Object(map) => {
            for (key, val) in map {
                // A secret can hide in a key as easily as a value (the wire
                // scrub in engine/model/redact.rs scrubs keys too), so scan both.
                push_string_matches(table, key, seen, out);
                collect_json_matches(table, val, seen, out);
            }
        }
        // A table literal can also appear as a non-string scalar — a numeric PIN
        // in `{"pin":1234}`, a bool-shaped token — where a string-only walk would
        // miss it (G4b). Match the scalar's canonical JSON text (`1234`,
        // `true`); a `null` carries no literal. The canonical text can BE the
        // secret, so hold it in a zeroizing frame that wipes on drop (G4c). This
        // is table-match-only, so an ordinary number absent from the table never
        // matches.
        Value::Bool(_) | Value::Number(_) => {
            let canonical = zeroize::Zeroizing::new(value.to_string());
            push_string_matches(table, canonical.as_str(), seen, out);
        }
        Value::Null => {}
    }
}

fn push_string_matches(
    table: &crate::redact::RedactionTable,
    s: &str,
    seen: &mut std::collections::HashSet<String>,
    out: &mut Vec<crate::redact::MatchedLiteral>,
) {
    for m in crate::redact::match_sensitive_literals(table, s) {
        if seen.insert(m.literal.clone()) {
            out.push(m);
        }
    }
}

/// Visit every JSON-value secret-bearing column of a `tool_call_events` row —
/// the model-supplied args (`original_input_json` / `wire_input_json`) and the
/// post-result `hint`. This is the SINGLE source of truth for those columns:
/// both the match/journal side ([`match_literals_in_tool_row`]) and the
/// fail-closed scrub side ([`Session::persist_redacted_tool_call`]) drive
/// through it, so a column added here is covered on BOTH sides — or on neither —
/// never silently half-covered (the drift that let `path`/`parent_call_id` slip
/// when the two sides kept separate hand-maintained lists).
fn for_each_tool_row_json_secret_column<F: FnMut(&mut Value)>(
    event: &mut crate::db::tool_calls::ToolCallEvent,
    mut visit: F,
) {
    visit(&mut event.original_input_json);
    visit(&mut event.wire_input_json);
    if let Some(hint) = event.hint.as_mut() {
        visit(hint);
    }
}

/// Visit every scalar (String) secret-bearing column of a `tool_call_events` row
/// that can carry a model/provider-derived literal — everything except the JSON
/// columns above and the structural id/enum/numeric columns we control
/// (`event_id`, `session_id`, `parent_child_index`, timestamps, `recovery_*`,
/// `exit_code`, booleans, `shape_fingerprint`, `llm_mode`, `provider`/`model`
/// names, `project_id`/`project_root`, `provider_call_id_source`, `wire_api`,
/// `provider_family`). SINGLE source of truth: both the match/journal side and
/// the fail-closed scrub side drive through it, so match==scrub is structurally
/// guaranteed — adding a column here covers both sides, omitting it covers
/// neither, and there is no second hand-maintained list to drift (the root cause
/// that previously left `path` and `parent_call_id` un-scrubbed).
fn for_each_tool_row_scalar_secret_column<F: FnMut(&mut String)>(
    event: &mut crate::db::tool_calls::ToolCallEvent,
    mut visit: F,
) {
    visit(&mut event.output);
    visit(&mut event.call_id);
    if let Some(parent_call_id) = event.parent_call_id.as_mut() {
        visit(parent_call_id);
    }
    visit(&mut event.agent);
    visit(&mut event.tool);
    if let Some(path) = event.path.as_mut() {
        visit(path);
    }
    if let Some(mcp_server) = event.mcp_server.as_mut() {
        visit(mcp_server);
    }
    if let Some(provider_item_id) = event.provider_item_id.as_mut() {
        visit(provider_item_id);
    }
    if let Some(provider_call_id) = event.provider_call_id.as_mut() {
        visit(provider_call_id);
    }
}

/// Match the DISTINCT redaction-table literals across EVERY secret-bearing
/// column of one `tool_call_events` audit row, driving through the SAME
/// [`for_each_tool_row_json_secret_column`] / [`for_each_tool_row_scalar_secret_column`]
/// enumerations the fail-closed scrub uses — so what journals on success is
/// exactly what scrubs on failure (decision 12). Takes `&mut` only to share
/// those one-source-of-truth visitors; it reads and never mutates. Distinct-by-
/// literal across all columns so each table entry journals once for the row.
fn match_literals_in_tool_row(
    table: &crate::redact::RedactionTable,
    event: &mut crate::db::tool_calls::ToolCallEvent,
) -> Vec<crate::redact::MatchedLiteral> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for_each_tool_row_json_secret_column(event, |value| {
        collect_json_matches(table, value, &mut seen, &mut out);
    });
    for_each_tool_row_scalar_secret_column(event, |column| {
        push_string_matches(table, column.as_str(), &mut seen, &mut out);
    });
    out
}

/// Fail-closed scrub of a plain string (the audit row's `output`) against
/// `table` (decision 12): the string analog of [`scrub_body_fail_closed`],
/// forcing enforcement so the `redact.enabled = false` opt-out cannot leave a
/// matched secret in a persisted fallback body.
fn scrub_string_fail_closed(s: &str, table: &crate::redact::RedactionTable) -> String {
    if table.disabled() {
        table.enforced().scrub(s)
    } else {
        table.scrub(s)
    }
}

/// Fail-closed scrub of a JSON body against `table` (decision 12). Forces
/// enforcement so the `redact.enabled = false` opt-out cannot leave a matched
/// secret in a persisted fallback body: decision 12 is fail-closed regardless of
/// the live opt-out, mirroring [`crate::redact::match_sensitive_literals`], which
/// also ignores `disabled`. Enforcing clones the table's secret-bearing entries,
/// so we only pay that on the rare disabled path; the common (and always the
/// persisted-table) case scrubs the table in place.
fn scrub_body_fail_closed(value: &Value, table: &crate::redact::RedactionTable) -> Value {
    if table.disabled() {
        scrub_matched_literals_in_json(value, &table.enforced())
    } else {
        scrub_matched_literals_in_json(value, table)
    }
}

/// Scrub every table literal from the DECODED string leaves, object keys, AND
/// non-string scalar leaves of a parsed JSON value, using the production
/// overlap-safe Aho-Corasick scrub ([`crate::redact::RedactionTable::scrub`],
/// leftmost-longest) rather than a naive per-literal `str::replace`. Leftmost-
/// longest is what makes overlapping table literals safe: with both `secret` and
/// `secretX` registered, `secretX` is replaced as one whole match and `secret`
/// only where it stands alone — the old sequential replace scrubbed `secret`
/// first and left the longer match's `X` suffix raw (G4a). Because it shares the
/// table's matcher with [`match_literals_in_json`], the match and scrub sides
/// stay semantically identical.
///
/// Operating on the parsed value — not a string-replace over the serialized blob
/// — keeps the scrub JSON-escape-safe (F2, the mirror of
/// [`match_literals_in_json`]) and always yields re-serializable JSON (the
/// placeholder carries no JSON-special characters). `table` MUST already be
/// enforcing (its callers go through [`scrub_body_fail_closed`]); a scalar leaf
/// whose canonical form matches becomes a JSON string carrying the scrubbed form
/// (a scrubbed number is no longer a valid JSON number), so the document stays
/// valid JSON.
///
/// The production scrub never copies the matched (secret) bytes into its output
/// — matched spans are replaced, not carried — so unlike the old
/// `s.to_string()` + `replace` chain this path holds no un-zeroized plaintext
/// copy of a string secret (G4c). The one transient plaintext a scalar secret
/// can produce (its canonical text) is held in [`zeroize::Zeroizing`].
fn scrub_matched_literals_in_json(value: &Value, table: &crate::redact::RedactionTable) -> Value {
    match value {
        Value::String(s) => Value::String(table.scrub(s)),
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| scrub_matched_literals_in_json(item, table))
                .collect(),
        ),
        Value::Object(map) => {
            let mut out = serde_json::Map::with_capacity(map.len());
            for (key, val) in map {
                out.insert(table.scrub(key), scrub_matched_literals_in_json(val, table));
            }
            Value::Object(out)
        }
        Value::Bool(_) | Value::Number(_) => scrub_scalar_leaf(value, table),
        Value::Null => value.clone(),
    }
}

/// Scrub one JSON scalar (number/bool) leaf: if its canonical JSON text contains
/// a table literal, return a JSON string carrying the scrubbed form; otherwise
/// the scalar is returned untouched (table-match-only — an ordinary number never
/// converts). The canonical text can itself BE the secret (a numeric PIN), so it
/// is held in [`zeroize::Zeroizing`] and wiped on drop (G4c).
fn scrub_scalar_leaf(value: &Value, table: &crate::redact::RedactionTable) -> Value {
    let canonical = zeroize::Zeroizing::new(value.to_string());
    let scrubbed = table.scrub(canonical.as_str());
    if scrubbed.as_str() == canonical.as_str() {
        value.clone()
    } else {
        Value::String(scrubbed)
    }
}

/// Closed classification of a trusted model-authored event to its protected
/// redaction-history artifact kind (decision 10.3): assistant/provider output is
/// a `Response`, tool call / result payloads are `Tool`, everything else `Event`.
fn event_artifact_kind(
    kind: crate::db::session_log::SessionEventKind,
) -> crate::redact::protected_redaction_history::RedactionArtifactKind {
    use crate::db::session_log::SessionEventKind as K;
    use crate::redact::protected_redaction_history::RedactionArtifactKind as A;
    match kind {
        K::AssistantMessage => A::Response,
        K::ToolCall | K::ToolCallStarted | K::ToolCallCompleted => A::Tool,
        _ => A::Event,
    }
}

/// Canonical artifact id for one immutable per-attempt inference row keyed
/// `(call_id, ordinal)`. `close-untrusted-provider-wire-and-type-sealed-entries`
/// keyed the row by the composite PK and established no separate string form;
/// this mirrors the export's per-attempt file suffix (`…_o{ordinal}`).
fn attempt_artifact_id(call_id: &str, ordinal: i64) -> String {
    format!("{call_id}_o{ordinal}")
}

/// Test-only mid-transaction fault seam (decision 10.2 AC9). Because a
/// [`crate::redact::protected_redaction_history::ProtectedRedactionHistory`]
/// handle is created fresh per journal write, the seam is a process-global flag
/// checked inside the composing transaction — nextest runs each test in its own
/// process, so the flag never leaks across tests. When set, the transaction
/// bails AFTER the artifact-row write and BEFORE the journal attach, proving
/// neither side commits alone.
#[cfg(test)]
pub(crate) mod journal_fault {
    use std::sync::atomic::{AtomicBool, Ordering};

    static FAIL_AFTER_ARTIFACT_ROW: AtomicBool = AtomicBool::new(false);

    /// Arm/disarm the mid-transaction fault.
    pub(crate) fn set_fail_after_artifact_row(fail: bool) {
        FAIL_AFTER_ARTIFACT_ROW.store(fail, Ordering::SeqCst);
    }

    pub(super) fn should_fail_after_artifact_row() -> bool {
        FAIL_AFTER_ARTIFACT_ROW.load(Ordering::SeqCst)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ModelSwitchAudit<'a> {
    pub from_provider: Option<&'a str>,
    pub from_model: Option<&'a str>,
    pub to_provider: &'a str,
    pub to_model: &'a str,
    pub trigger: ModelSwitchTrigger,
    pub outcome: ModelSwitchOutcome,
    pub error: Option<&'a str>,
}

impl Session {
    fn session_event_provenance_for(
        &self,
        kind: crate::db::session_log::SessionEventKind,
        frame: Option<SessionEventModelFrame<'_>>,
        data: &Value,
    ) -> Option<SessionEventProvenance> {
        if !event_kind_is_model_authored(kind) {
            return None;
        }
        let provider_id = frame
            .map(|frame| frame.provider_id.to_string())
            .or_else(|| {
                data.get("provider")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .or_else(|| self.active_provider())?;
        let model_id = frame
            .map(|frame| frame.model_id.to_string())
            .or_else(|| {
                data.get("model")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .or_else(|| self.active_model())?;
        let snapshot = frame.map(|frame| frame.config.snapshot())?;
        let llm_mode =
            snapshot
                .providers
                .resolve_mode(&provider_id, &model_id, snapshot.extended.llm_mode);
        // Resolve trust through the SAME frame method a co-persisted tool_call
        // audit row uses (`SessionEventModelFrame::resolved_model_trust`), so the
        // event's journal-vs-scrub decision and the audit row's are ONE source of
        // truth and can never diverge (finding r11-3 follow-up). `frame` is
        // guaranteed `Some` here — the `snapshot` bind above returns early
        // otherwise — and when present `provider_id`/`model_id` equal its fields,
        // so the fallback computes the identical value and never actually runs.
        let model_trust = frame
            .map(|frame| frame.resolved_model_trust())
            .unwrap_or_else(|| snapshot.providers.resolve_trust(&provider_id, &model_id));
        Some(SessionEventProvenance {
            provider_id,
            model_id,
            llm_mode,
            model_trust,
        })
    }

    pub async fn record_event_with_model_frame(
        &self,
        kind: crate::db::session_log::SessionEventKind,
        agent: Option<&str>,
        call_id: Option<&str>,
        frame: SessionEventModelFrame<'_>,
        data: &Value,
    ) -> Result<i64> {
        self.record_event_with_origin_and_frame(kind, agent, call_id, None, Some(frame), data)
            .await
    }

    /// Config-frame entry point (e.g. the driver's subagent-routing amend) that
    /// resolves provider/model from `data`/active model rather than a live
    /// `Model`. `session_table` is the caller's REAL pre-policy session table
    /// (F3): a trusted model-authored event journals its table-matched literals
    /// against it, so a session-table literal appearing in a routing label /
    /// task-id is captured. Callers with no live table pass
    /// [`crate::redact::RedactionTable::empty`] (journals nothing).
    pub async fn record_event_with_config(
        &self,
        kind: crate::db::session_log::SessionEventKind,
        agent: Option<&str>,
        call_id: Option<&str>,
        config: &crate::daemon::session_worker::SessionConfigHandle,
        session_table: &crate::redact::RedactionTable,
        data: &Value,
    ) -> Result<i64> {
        let active_provider = self.active_provider();
        let active_model = self.active_model();
        let provider_id = data
            .get("provider")
            .and_then(Value::as_str)
            .or(active_provider.as_deref())
            .context("model-authored event has no provider frame")?;
        let model_id = data
            .get("model")
            .and_then(Value::as_str)
            .or(active_model.as_deref())
            .context("model-authored event has no model frame")?;
        self.record_event_with_model_frame(
            kind,
            agent,
            call_id,
            SessionEventModelFrame {
                provider_id,
                model_id,
                config,
                session_table,
            },
            data,
        )
        .await
    }

    /// Convert an in-memory [`ToolCallRow`] to the persisted [`ToolCallEvent`],
    /// stamping session/project/model provenance and the cockpit version.
    fn tool_call_event_from_row(&self, row: ToolCallRow) -> ToolCallEvent {
        let provider = self.active_provider().unwrap_or_default();
        let model = self.active_model().unwrap_or_default();
        let project_root = self.project_root.to_string_lossy().into_owned();
        ToolCallEvent {
            event_id: row.event_id,
            session_id: self.id,
            call_id: row.call_id,
            parent_call_id: row.parent_call_id,
            parent_child_index: row.parent_child_index,
            provider_item_id: row.identity.provider_item_id,
            provider_call_id: row.identity.provider_call_id,
            provider_call_id_source: row.identity.provider_call_id_source,
            wire_api: row.identity.wire_api,
            provider_family: row.identity.provider_family,
            timestamp: row.timestamp.timestamp(),
            model,
            provider,
            project_id: self.project_id.clone(),
            project_root,
            agent: row.agent,
            tool: row.tool,
            mcp_server: row.mcp_server,
            path: row.path,
            recovery: row.recovery,
            hard_fail: row.hard_fail,
            exit_code: row.exit_code,
            sandbox_enabled: row.sandbox_enabled,
            sandboxed: row.sandboxed,
            sandbox_unavailable_reason: row.sandbox_unavailable_reason,
            original_input_json: row.original_input_json,
            wire_input_json: row.wire_input_json,
            output: row.output,
            truncated: row.truncated,
            duration_ms: row.duration_ms,
            cockpit_version: Some(env!("CARGO_PKG_VERSION").to_string()),
            llm_mode: Some(row.llm_mode.as_str().to_string()),
            shape_fingerprint: row.shape_fingerprint,
            hint: row.hint,
        }
    }

    /// Append one tool-call audit row to the §15b table (plain insert). The row
    /// is persisted verbatim. Used by replay/rehydrate and driver-synthesized
    /// paths whose args are not a fresh model-authored payload. The three live
    /// tool-call dispatch paths that co-persist raw model args alongside a
    /// journaled session event use [`Self::record_tool_call_journaled`] instead.
    pub async fn record_tool_call(&self, row: ToolCallRow) -> Result<()> {
        let event = self.tool_call_event_from_row(row);
        self.db
            .insert_tool_call(&event)
            .await
            .context("inserting tool_call_event")
    }

    /// Like [`Self::record_tool_call`] but for the three live tool-call dispatch
    /// paths (ordinary tool call, `schedule` meta-tool, MCP child) that
    /// co-persist the model-supplied args RAW into `tool_call_events` alongside
    /// the model-authored session event (decision 12 / finding r11-3).
    ///
    /// `session_table` is the caller's PRE-POLICY session redaction table (never
    /// the trusted-empty effective table) and `target_trusted` is the authoring
    /// model's trust bit — the SAME frame used to journal the co-persisted
    /// session event. For a TRUSTED author (and a journaling session) the row's
    /// table-matched literals (across the args AND the co-persisted output) are
    /// journaled to protected redaction history — artifact kind `Tool`,
    /// `artifact_id = event_id` — in the SAME transaction as the row insert, so
    /// on success the audit row carries its own history ref (export redacts) and
    /// on any journaling failure the stored args/output are fail-closed scrubbed
    /// with no history row: the audit row never persists a matched literal that
    /// has no protected-history row, and no ref points at a non-existent row.
    ///
    /// An UNTRUSTED author (args already post-redaction) and a scratch session
    /// ([`Self::allow_unjournaled_inference`]) keep the plain insert — the
    /// pre-existing behavior — journaling nothing.
    pub async fn record_tool_call_journaled(
        &self,
        row: ToolCallRow,
        session_table: &crate::redact::RedactionTable,
        target_trusted: bool,
    ) -> Result<()> {
        let event = self.tool_call_event_from_row(row);
        // Untrusted author or scratch/daemon-less session: today's plain insert,
        // journal nothing. Untrusted args are already post-redaction and must
        // never create history rows.
        if !target_trusted || self.unjournaled_inference_allowed() {
            return self
                .db
                .insert_tool_call(&event)
                .await
                .context("inserting tool_call_event");
        }
        self.journal_trusted_tool_call(event, session_table).await
    }

    /// Journal the table-matched literals of a TRUSTED tool-call audit row
    /// atomically with the row insert (decision 10.3 + 12), mirroring
    /// [`Self::journal_trusted_inference_attempt`].
    ///
    /// Off the DB thread we scan the args + output against the pre-policy session
    /// table and `prepare_append` each match. If ANY prepare fails we fail closed
    /// (decision 12): the matched literals are scrubbed from the args/output with
    /// the table's generic placeholder, the redacted row is persisted via the
    /// normal insert, no history row is written, and a warning is surfaced — the
    /// turn is NOT aborted. Otherwise the row insert and every prepared append +
    /// artifact ref (`Tool`, `event_id`) commit in one transaction; any error
    /// rolls them all back together and then falls closed to the scrubbed row.
    async fn journal_trusted_tool_call(
        &self,
        mut event: ToolCallEvent,
        session_table: &crate::redact::RedactionTable,
    ) -> Result<()> {
        // JSON-value-aware match (F2) over EVERY secret-bearing column (args,
        // hint, output, and the scalar columns incl. `path`): scan each DECODED
        // string, not the escaped serialized blob. `&mut` only shares the
        // one-source-of-truth column visitors; the match does not mutate.
        let matches = match_literals_in_tool_row(session_table, &mut event);
        if matches.is_empty() {
            // No table-matched literals: nothing to journal, plain insert.
            return self
                .db
                .insert_tool_call(&event)
                .await
                .context("inserting tool_call_event");
        }

        let resolver = self.redaction_key_resolver().clone();
        let history = crate::redact::protected_redaction_history::ProtectedRedactionHistory::new(
            &self.db,
            resolver.as_ref(),
        );
        let session_id_str = self.id.to_string();
        let mut prepared = Vec::with_capacity(matches.len());
        for m in &matches {
            let literal = match matched_to_protected_literal(m) {
                Ok(literal) => literal,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "trusted tool-call journaling: literal rejected; persisting redacted row"
                    );
                    return self.persist_redacted_tool_call(event, session_table).await;
                }
            };
            match history.prepare_append(&session_id_str, literal).await {
                Ok(p) => prepared.push(p),
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "trusted tool-call journaling: prepare_append failed; persisting redacted row"
                    );
                    return self.persist_redacted_tool_call(event, session_table).await;
                }
            }
        }

        // The single artifact this row is: the immutable audit row keyed by its
        // `event_id` (artifact kind `Tool`).
        let artifact_id = event.event_id.to_string();
        // Clone for the move-closure; keep `event` for the decision-12 fallback.
        let event_for_txn = event.clone();
        let journal_result = self
            .db
            .transaction(move |conn| {
                Db::insert_tool_call_conn(conn, &event_for_txn)?;
                // Mid-transaction failure seam (AC9): force an error AFTER the
                // audit-row write and BEFORE the journal attach to prove neither
                // side can commit alone.
                #[cfg(test)]
                if journal_fault::should_fail_after_artifact_row() {
                    anyhow::bail!("injected mid-transaction tool_call journal fault (test seam)");
                }
                let refs = [crate::redact::protected_redaction_history::ArtifactRef::new(
                    crate::redact::protected_redaction_history::RedactionArtifactKind::Tool,
                    artifact_id,
                )];
                for prepared in &prepared {
                    crate::redact::protected_redaction_history::append_and_attach_conn(
                        conn, prepared, &refs,
                    )?;
                }
                Ok(())
            })
            .await;

        // Decision-12 fail-closed for a journal-TRANSACTION failure (F1): the
        // audit row + history/refs roll back together ATOMICALLY (AC9), THEN the
        // matched-literal-scrubbed row is persisted via a separate non-journaling
        // insert (no history); the turn is not aborted.
        if let Err(e) = journal_result {
            tracing::warn!(
                error = %e,
                "trusted tool-call journaling: transaction failed; persisting redacted row"
            );
            return self.persist_redacted_tool_call(event, session_table).await;
        }
        Ok(())
    }

    /// Fail-closed audit-row persistence (decision 12): scrub every table literal
    /// from EVERY secret-bearing column by driving through the SAME
    /// [`for_each_tool_row_json_secret_column`] / [`for_each_tool_row_scalar_secret_column`]
    /// visitors the match/journal side uses — so the scrub set is structurally
    /// identical to the journal set (no second hand-maintained list to drift; the
    /// root cause that previously left `path` and `parent_call_id` un-scrubbed).
    /// Then persist the row through the normal insert with NO history rows. A
    /// scrub is a no-op on any column that carries no table literal, so ordinary
    /// ids/names/paths are untouched in normal operation. Columns NOT in those two
    /// visitors are intentionally excluded (per their doc comments): the
    /// structural id columns we mint, the config/host identity columns, the closed
    /// enum/label columns, and the derived/constant columns — none carry model
    /// text.
    async fn persist_redacted_tool_call(
        &self,
        mut event: ToolCallEvent,
        session_table: &crate::redact::RedactionTable,
    ) -> Result<()> {
        for_each_tool_row_json_secret_column(&mut event, |value| {
            *value = scrub_body_fail_closed(value, session_table);
        });
        for_each_tool_row_scalar_secret_column(&mut event, |column| {
            *column = scrub_string_fail_closed(column.as_str(), session_table);
        });
        self.db
            .insert_tool_call(&event)
            .await
            .context("inserting redacted tool_call_event")
    }

    /// Record provider-reported token usage for a round-trip: persist
    /// it to `inference_calls` for `/stats` and store the latest value
    /// on the session so the TUI can show it in the context indicator.
    /// No-op (for the DB write) when the active provider/model isn't set
    /// on the session (background calls during startup).
    ///
    /// `call_id` is the round-trip's id — the SAME value used to key the
    /// captured request body in `inference_requests`
    /// ([`Self::record_inference_request`]) so the metadata row and the
    /// full payload join on `call_id` (session-log-export Part A).
    pub async fn record_usage(
        &self,
        call_id: Uuid,
        usage: crate::tokens::TokenUsage,
    ) -> Result<()> {
        self.record_usage_inner(call_id, usage, false).await
    }

    /// Like [`Self::record_usage`] but flags the persisted `inference_calls`
    /// row as a utility / background call (the `/export debug` bundle routes
    /// it into `inference_requests_utility/`). Used by background round-trips
    /// (the `/compact` handoff brief, etc.) that aren't foreground user turns.
    pub async fn record_usage_utility(
        &self,
        call_id: Uuid,
        usage: crate::tokens::TokenUsage,
    ) -> Result<()> {
        self.record_usage_inner(call_id, usage, true).await
    }

    async fn record_usage_inner(
        &self,
        call_id: Uuid,
        usage: crate::tokens::TokenUsage,
        is_utility: bool,
    ) -> Result<()> {
        *self.last_usage.lock().unwrap() = Some(usage);

        let (Some(provider), Some(model)) = (self.active_provider(), self.active_model()) else {
            return Ok(());
        };
        let row = crate::db::inference_calls::InferenceCallRow {
            call_id,
            session_id: self.id,
            project_id: self.project_id.clone(),
            project_root: self.project_root.to_string_lossy().into_owned(),
            model,
            provider,
            timestamp: Utc::now().timestamp(),
            input_tokens: usage.input_tokens as i64,
            output_tokens: usage.output_tokens as i64,
            cached_input_tokens: usage.cached_input_tokens as i64,
            cache_creation_input_tokens: usage.cache_creation_input_tokens as i64,
            cost_usd_micros: None,
            is_utility,
        };
        self.db
            .insert_inference_call(&row)
            .await
            .context("inserting inference_call")
    }

    /// Insert the IMMUTABLE post-render request body for one dispatched-target
    /// attempt keyed `(call_id, ordinal)` (session-log-export Part A) with
    /// initial status `pending`. Always-on — every attempt, every session. The
    /// payload is the exact as-sent form for that target; no second redaction
    /// pass is applied and it is never rewritten. Phase timestamps and the
    /// terminal status are filled by [`Self::advance_inference_request`]. A
    /// second body write to an existing `(call_id, ordinal)` errors.
    ///
    /// `session_table` is the PRE-POLICY session redaction table (never the
    /// trusted-empty effective table) and `target_trusted` is the target route's
    /// trust bit. When the target is trusted (and the session has not opted out
    /// of journaling), the table-matched literals in the payload are journaled to
    /// protected redaction history in the SAME transaction as the payload insert
    /// (decision 10.2): the payload row and the history/ref rows commit together
    /// or not at all. An untrusted target (payload already post-redaction) and a
    /// scratch session ([`Self::allow_unjournaled_inference`]) journal nothing.
    pub async fn insert_inference_attempt(
        &self,
        call_id: Uuid,
        ordinal: i64,
        payload: &Value,
        meta: crate::db::session_log::InferenceAttemptMeta<'_>,
        provenance: Option<(Uuid, i64)>,
        session_table: &crate::redact::RedactionTable,
        target_trusted: bool,
    ) -> Result<()> {
        // Untrusted target or scratch/daemon-less session: keep today's
        // insert-only path, journal nothing. Untrusted payloads are already
        // post-redaction and must never create history rows.
        if !target_trusted || self.unjournaled_inference_allowed() {
            return self
                .db
                .insert_inference_request(
                    &call_id.to_string(),
                    ordinal,
                    self.id,
                    payload,
                    meta,
                    provenance,
                )
                .await
                .context("inserting inference_request");
        }
        self.journal_trusted_inference_attempt(
            call_id,
            ordinal,
            payload,
            meta,
            provenance,
            session_table,
        )
        .await
    }

    /// Advance one attempt's lifecycle status (monotonically) and fill phase
    /// columns. Never touches the immutable `payload_json`.
    pub async fn advance_inference_request(
        &self,
        call_id: Uuid,
        ordinal: i64,
        status: crate::db::session_log::InferenceRequestStatus,
        phases: crate::db::session_log::InferencePhaseTimings,
    ) -> Result<()> {
        self.db
            .advance_inference_request(&call_id.to_string(), ordinal, status, phases)
            .await
            .context("advancing inference_request status")
    }

    /// Convenience for single-attempt utility writes (e.g. the `/compact`
    /// brief): insert the body at ordinal 0, then advance to `status`.
    pub async fn record_inference_request(
        &self,
        call_id: Uuid,
        payload: &Value,
        status: crate::db::session_log::InferenceRequestStatus,
        session_table: &crate::redact::RedactionTable,
        target_trusted: bool,
    ) -> Result<()> {
        self.insert_inference_attempt(
            call_id,
            0,
            payload,
            crate::db::session_log::InferenceAttemptMeta::default(),
            None,
            session_table,
            target_trusted,
        )
        .await?;
        self.advance_inference_request(
            call_id,
            0,
            status,
            crate::db::session_log::InferencePhaseTimings::default(),
        )
        .await
    }

    /// Journal the table-matched literals of a TRUSTED inference-attempt payload
    /// atomically with the immutable payload insert (decision 10.2 + 12).
    ///
    /// Off the DB thread we scan the serialized payload against the pre-policy
    /// session table and `prepare_append` each match. If ANY prepare fails we
    /// fail closed (decision 12): the matched literals are scrubbed from the body
    /// with the table's generic placeholder, the redacted body is persisted via
    /// the normal insert, no history row is written, and a warning is surfaced —
    /// the turn is NOT aborted. Otherwise the payload row and every prepared
    /// append + artifact ref are committed in one transaction; any error rolls
    /// back all of them together. Journaling runs only when the insert actually
    /// creates the `(call_id, ordinal)` row (a plain INSERT that errors on a
    /// duplicate), so a re-insert never re-journals.
    async fn journal_trusted_inference_attempt(
        &self,
        call_id: Uuid,
        ordinal: i64,
        payload: &Value,
        meta: crate::db::session_log::InferenceAttemptMeta<'_>,
        provenance: Option<(Uuid, i64)>,
        session_table: &crate::redact::RedactionTable,
    ) -> Result<()> {
        // JSON-value-aware match (F2): scan each DECODED string in the payload,
        // not the escaped serialized blob, so a literal with JSON-special
        // characters is still found.
        let matches = match_literals_in_json(session_table, payload);
        if matches.is_empty() {
            // No table-matched literals: nothing to journal, plain insert.
            return self
                .db
                .insert_inference_request(
                    &call_id.to_string(),
                    ordinal,
                    self.id,
                    payload,
                    meta,
                    provenance,
                )
                .await
                .context("inserting inference_request");
        }
        let payload_json = serde_json::to_string(payload)
            .context("serializing inference payload for journaling")?;

        let resolver = self.redaction_key_resolver().clone();
        let history = crate::redact::protected_redaction_history::ProtectedRedactionHistory::new(
            &self.db,
            resolver.as_ref(),
        );
        let session_id_str = self.id.to_string();
        let mut prepared = Vec::with_capacity(matches.len());
        for m in &matches {
            let literal = match matched_to_protected_literal(m) {
                Ok(literal) => literal,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "trusted inference journaling: literal rejected; persisting redacted body"
                    );
                    return self
                        .persist_redacted_inference(
                            call_id,
                            ordinal,
                            payload,
                            session_table,
                            meta,
                            provenance,
                        )
                        .await;
                }
            };
            match history.prepare_append(&session_id_str, literal).await {
                Ok(p) => prepared.push(p),
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "trusted inference journaling: prepare_append failed; persisting redacted body"
                    );
                    return self
                        .persist_redacted_inference(
                            call_id,
                            ordinal,
                            payload,
                            session_table,
                            meta,
                            provenance,
                        )
                        .await;
                }
            }
        }

        // Refs shared by every prepared append: the logical request (keyed by
        // `call_id`) and this immutable per-attempt row (keyed by the canonical
        // `(call_id, ordinal)` string).
        let call_id_str = call_id.to_string();
        let refs = vec![
            crate::redact::protected_redaction_history::ArtifactRef::new(
                crate::redact::protected_redaction_history::RedactionArtifactKind::Request,
                call_id_str.clone(),
            ),
            crate::redact::protected_redaction_history::ArtifactRef::new(
                crate::redact::protected_redaction_history::RedactionArtifactKind::Attempt,
                attempt_artifact_id(&call_id_str, ordinal),
            ),
        ];

        let session_id = self.id;
        let provider = meta.provider.map(str::to_owned);
        let model = meta.model.map(str::to_owned);
        let trust = meta.trust.map(str::to_owned);
        let journal_result = self
            .db
            .transaction(move |conn| {
                let meta = crate::db::session_log::InferenceAttemptMeta {
                    provider: provider.as_deref(),
                    model: model.as_deref(),
                    trust: trust.as_deref(),
                };
                let inserted = Db::insert_inference_attempt_body_conn(
                    conn,
                    &call_id_str,
                    ordinal,
                    session_id,
                    &payload_json,
                    meta,
                    provenance,
                )?;
                // Mid-transaction failure seam (AC9): force an error AFTER the
                // inference-row write and BEFORE the journal attach to prove
                // neither side can commit alone.
                #[cfg(test)]
                if journal_fault::should_fail_after_artifact_row() {
                    anyhow::bail!("injected mid-transaction inference journal fault (test seam)");
                }
                // Journal only when this insert actually created the row.
                if inserted > 0 {
                    for prepared in &prepared {
                        crate::redact::protected_redaction_history::append_and_attach_conn(
                            conn, prepared, &refs,
                        )?;
                    }
                }
                Ok(())
            })
            .await;

        // Decision-12 fail-closed for a journal-TRANSACTION failure (F1): a
        // failure of the body insert, an `append_and_attach_conn`, or the test
        // seam rolls the whole transaction back ATOMICALLY (nothing — neither the
        // inference row nor any history/ref — commits alone, preserving AC9).
        // Only THEN do we persist the matched-literal-scrubbed body via a separate
        // non-journaling insert (no history), warn, and continue the turn rather
        // than propagate the error and abort it.
        if let Err(e) = journal_result {
            tracing::warn!(
                error = %e,
                "trusted inference journaling: transaction failed; persisting redacted body"
            );
            return self
                .persist_redacted_inference(
                    call_id,
                    ordinal,
                    payload,
                    session_table,
                    meta,
                    provenance,
                )
                .await;
        }
        Ok(())
    }

    /// Fail-closed body persistence (decision 12): scrub every table literal
    /// WITHIN the parsed JSON string values/keys/scalar leaves with the table's
    /// overlap-safe production scrub (F2 escape-safe), then persist the
    /// re-serialized body through the normal insert with NO history rows.
    async fn persist_redacted_inference(
        &self,
        call_id: Uuid,
        ordinal: i64,
        payload: &Value,
        session_table: &crate::redact::RedactionTable,
        meta: crate::db::session_log::InferenceAttemptMeta<'_>,
        provenance: Option<(Uuid, i64)>,
    ) -> Result<()> {
        let redacted = scrub_body_fail_closed(payload, session_table);
        self.db
            .insert_inference_request(
                &call_id.to_string(),
                ordinal,
                self.id,
                &redacted,
                meta,
                provenance,
            )
            .await
            .context("inserting redacted inference_request")
    }

    /// Persist (or update) one tandem (shadow) inference record for
    /// model-comparison mode (implementation note),
    /// keyed by the per-row `id`. Unlike [`Self::record_inference_request`]
    /// (request body only), a tandem record additionally stores the full raw
    /// `response` + `usage`, and links back to the main call it shadows via
    /// `parent_call_id` (+ `parent_seq`/`agent` for timeline alignment).
    /// Written at dispatch (`pending`, no response) and again on settle
    /// (terminal status + captured response/usage).
    ///
    /// `session_table` is the tandem target's PRE-POLICY session redaction table
    /// (never the trusted-empty effective table) and `target_trusted` is that
    /// target route's trust bit. A tandem target runs on its OWN trust: a TRUSTED
    /// tandem keeps raw custody, so BOTH the assembled `request` body AND the
    /// captured `response` it emits are persisted RAW and can carry a session-
    /// table literal (`dispatch.rs` `complete_tandem`/`assemble_dispatch_request`
    /// keep the raw history for a trusted route; the response echoes what that
    /// route saw). Those raw literals are NOT otherwise journaled — the MAIN call
    /// journals against the MAIN model's trust, which is independent of a tandem
    /// target's — so when the target is trusted (and journaling is not opted out)
    /// this journals every table-matched literal in the row to protected redaction
    /// history in the SAME transaction as the row write (decision 10.2/11/12). An
    /// UNTRUSTED tandem sends only the already-scrubbed body and never sees the raw
    /// literal, so its request/response are post-redaction and journal nothing; a
    /// scratch session ([`Self::allow_unjournaled_inference`]) journals nothing.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_tandem_inference(
        &self,
        id: &str,
        parent_call_id: &str,
        parent_seq: Option<i64>,
        agent: Option<&str>,
        provider: &str,
        model: &str,
        request: &Value,
        response: Option<&Value>,
        usage: Option<&Value>,
        status: crate::db::session_log::InferenceRequestStatus,
        session_table: &crate::redact::RedactionTable,
        target_trusted: bool,
    ) -> Result<()> {
        // Untrusted target or scratch/daemon-less session: today's plain upsert,
        // journal nothing. Both request and response are already post-redaction.
        if !target_trusted || self.unjournaled_inference_allowed() {
            return self
                .db
                .upsert_tandem_inference(
                    id,
                    self.id,
                    parent_call_id,
                    parent_seq,
                    agent,
                    provider,
                    model,
                    request,
                    response,
                    usage,
                    status,
                )
                .await
                .context("inserting tandem_inference");
        }
        self.journal_trusted_tandem_inference(
            id,
            parent_call_id,
            parent_seq,
            agent,
            provider,
            model,
            request,
            response,
            usage,
            status,
            session_table,
        )
        .await
    }

    /// Journal the table-matched literals of a TRUSTED tandem row (request +
    /// response) atomically with the row upsert (decision 10.2 + 12), mirroring
    /// [`Self::journal_trusted_inference_attempt`].
    ///
    /// Off the DB thread we scan each of the request and (when present) response
    /// JSON values against the pre-policy session table and `prepare_append` each
    /// match, tagging it with the artifact side it appeared in (`Request` /
    /// `Response`). If ANY prepare fails we fail closed (decision 12): the matched
    /// literals are scrubbed from BOTH bodies with the table's generic
    /// placeholder, the redacted row is persisted via the normal upsert, no
    /// history row is written, and a warning is surfaced — the write is never
    /// aborted. Otherwise the row upsert and every prepared append + artifact ref
    /// commit in one transaction; any error rolls them back together and then
    /// falls closed to the scrubbed row. The pending→settle upsert re-journals the
    /// request literals, but `append_and_attach_conn` deduplicates the history row
    /// and idempotently attaches the ref, so no double-count results.
    #[allow(clippy::too_many_arguments)]
    async fn journal_trusted_tandem_inference(
        &self,
        id: &str,
        parent_call_id: &str,
        parent_seq: Option<i64>,
        agent: Option<&str>,
        provider: &str,
        model: &str,
        request: &Value,
        response: Option<&Value>,
        usage: Option<&Value>,
        status: crate::db::session_log::InferenceRequestStatus,
        session_table: &crate::redact::RedactionTable,
    ) -> Result<()> {
        use crate::redact::protected_redaction_history::{
            PreparedProtectedAppend, RedactionArtifactKind,
        };
        let resolver = self.redaction_key_resolver().clone();
        let history = crate::redact::protected_redaction_history::ProtectedRedactionHistory::new(
            &self.db,
            resolver.as_ref(),
        );
        let session_id_str = self.id.to_string();
        // JSON-value-aware match (F2) over each side: the request column and the
        // response column are distinct artifacts, so a literal is tagged with the
        // side it appeared in for accurate provenance.
        let mut prepared: Vec<(PreparedProtectedAppend, RedactionArtifactKind)> = Vec::new();
        let sides: [(RedactionArtifactKind, Option<&Value>); 2] = [
            (RedactionArtifactKind::Request, Some(request)),
            (RedactionArtifactKind::Response, response),
        ];
        for (kind, value) in sides {
            let Some(value) = value else { continue };
            for m in &match_literals_in_json(session_table, value) {
                let literal = match matched_to_protected_literal(m) {
                    Ok(literal) => literal,
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "trusted tandem journaling: literal rejected; persisting redacted row"
                        );
                        return self
                            .persist_redacted_tandem(
                                id,
                                parent_call_id,
                                parent_seq,
                                agent,
                                provider,
                                model,
                                request,
                                response,
                                usage,
                                status,
                                session_table,
                            )
                            .await;
                    }
                };
                match history.prepare_append(&session_id_str, literal).await {
                    Ok(p) => prepared.push((p, kind)),
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "trusted tandem journaling: prepare_append failed; persisting redacted row"
                        );
                        return self
                            .persist_redacted_tandem(
                                id,
                                parent_call_id,
                                parent_seq,
                                agent,
                                provider,
                                model,
                                request,
                                response,
                                usage,
                                status,
                                session_table,
                            )
                            .await;
                    }
                }
            }
        }

        if prepared.is_empty() {
            // No table-matched literals in either body: nothing to journal.
            return self
                .db
                .upsert_tandem_inference(
                    id,
                    self.id,
                    parent_call_id,
                    parent_seq,
                    agent,
                    provider,
                    model,
                    request,
                    response,
                    usage,
                    status,
                )
                .await
                .context("inserting tandem_inference");
        }

        let session_id = self.id;
        let id_owned = id.to_owned();
        let parent_call_id_owned = parent_call_id.to_owned();
        let agent_owned = agent.map(str::to_owned);
        let provider_owned = provider.to_owned();
        let model_owned = model.to_owned();
        let request_owned = request.clone();
        let response_owned = response.cloned();
        let usage_owned = usage.cloned();
        let status_str = status.as_str();
        let ts_ms = crate::db::session_log::now_ms();
        let journal_result = self
            .db
            .transaction(move |conn| {
                // The pre-existing connection-scoped tandem upsert lets us compose
                // the row write and the protected-history attach in ONE transaction
                // (decision 10.2): they commit together or roll back together. (It
                // sets `ts_ms = excluded` rather than COALESCE-preserving it, a
                // negligible timeline-metadata difference for a trusted tandem's
                // settle write; never a redaction concern.)
                Db::upsert_tandem_inference_conn(
                    conn,
                    &id_owned,
                    session_id,
                    &parent_call_id_owned,
                    parent_seq,
                    agent_owned.as_deref(),
                    &provider_owned,
                    &model_owned,
                    ts_ms,
                    &request_owned,
                    response_owned.as_ref(),
                    usage_owned.as_ref(),
                    status_str,
                )?;
                // Mid-transaction failure seam (AC9): force an error AFTER the
                // tandem-row write and BEFORE the journal attach to prove neither
                // side can commit alone.
                #[cfg(test)]
                if journal_fault::should_fail_after_artifact_row() {
                    anyhow::bail!("injected mid-transaction tandem journal fault (test seam)");
                }
                for (prepared, kind) in &prepared {
                    let refs = [
                        crate::redact::protected_redaction_history::ArtifactRef::new(
                            *kind,
                            id_owned.clone(),
                        ),
                    ];
                    crate::redact::protected_redaction_history::append_and_attach_conn(
                        conn, prepared, &refs,
                    )?;
                }
                Ok(())
            })
            .await;

        // Decision-12 fail-closed for a journal-TRANSACTION failure (F1): the
        // tandem row + history/refs roll back together ATOMICALLY, THEN the
        // matched-literal-scrubbed row is persisted via a separate non-journaling
        // upsert (no history); the write is not aborted.
        if let Err(e) = journal_result {
            tracing::warn!(
                error = %e,
                "trusted tandem journaling: transaction failed; persisting redacted row"
            );
            return self
                .persist_redacted_tandem(
                    id,
                    parent_call_id,
                    parent_seq,
                    agent,
                    provider,
                    model,
                    request,
                    response,
                    usage,
                    status,
                    session_table,
                )
                .await;
        }
        Ok(())
    }

    /// Fail-closed tandem persistence (decision 12): scrub every table literal
    /// within BOTH the request and response JSON bodies with the table's
    /// overlap-safe production scrub (F2 escape-safe), then upsert the
    /// re-serialized row through the normal path with NO history rows.
    #[allow(clippy::too_many_arguments)]
    async fn persist_redacted_tandem(
        &self,
        id: &str,
        parent_call_id: &str,
        parent_seq: Option<i64>,
        agent: Option<&str>,
        provider: &str,
        model: &str,
        request: &Value,
        response: Option<&Value>,
        usage: Option<&Value>,
        status: crate::db::session_log::InferenceRequestStatus,
        session_table: &crate::redact::RedactionTable,
    ) -> Result<()> {
        let redacted_request = scrub_body_fail_closed(request, session_table);
        let redacted_response = response.map(|r| scrub_body_fail_closed(r, session_table));
        self.db
            .upsert_tandem_inference(
                id,
                self.id,
                parent_call_id,
                parent_seq,
                agent,
                provider,
                model,
                &redacted_request,
                redacted_response.as_ref(),
                usage,
                status,
            )
            .await
            .context("inserting redacted tandem_inference")
    }

    /// Snapshot the resolved agent-guidance file body at session start
    /// (live instructions-file diff injection, prompt
    /// `instructions-file-live-diff.md`). Called once when the session's
    /// system prompt is composed (the daemon session-worker spawn): the
    /// frozen system block carries this body, so it becomes the baseline a
    /// later in-place edit is diffed against.
    ///
    /// Resolves the same first-matching guidance file
    /// [`crate::engine::builtin`] bakes into the system block. When one
    /// resolves, stores `(path, hash)` on the session row and the body in
    /// the content-addressed `guidance_contents` table. When none resolves,
    /// clears the baseline (NULL) so the feature stays inert for this
    /// session. Best-effort: a failure here must never break session
    /// startup.
    pub async fn snapshot_guidance_baseline(&self, cwd: &std::path::Path) {
        let baseline = match crate::engine::builtin::load_agent_guidance(cwd) {
            Some((path, body)) => {
                let hash = crate::engine::guidance_diff::hash_contents(&body);
                if let Err(e) = self.db.put_guidance_contents(&hash, &body).await {
                    tracing::warn!(error = %e, "guidance baseline: storing contents failed");
                    return;
                }
                Some(crate::db::guidance::GuidanceBaseline {
                    path: path.display().to_string(),
                    hash,
                })
            }
            None => None,
        };
        if self.stage_pending_row(|row| {
            row.guidance_baseline_path = baseline.as_ref().map(|b| b.path.clone());
            row.guidance_baseline_hash = baseline.as_ref().map(|b| b.hash.clone());
        }) {
            return;
        }
        if let Err(e) = self
            .db
            .set_guidance_baseline(self.id, baseline.as_ref())
            .await
        {
            tracing::warn!(error = %e, "guidance baseline: setting baseline failed");
        }
    }

    /// Check the resolved guidance file for an in-place edit since the
    /// session's stored baseline, and — when one is found — return the
    /// synthetic system-message body to append at the end of history (live
    /// instructions-file diff injection). The returned string is the
    /// authoritative framing header + unified diff (or full contents); the
    /// caller scrubs it through [`crate::redact`] before appending, exactly
    /// like any other outbound content.
    ///
    /// Returns `None` (no injection) when:
    /// - no baseline was stored (no guidance file at session start), or
    /// - re-resolution finds no guidance file (deleted mid-session), or
    /// - re-resolution finds a *different* file than the baseline path
    ///   (the file switched — out of scope), or
    /// - the resolved file's hash is unchanged (idempotent: already at
    ///   baseline, nothing to inject).
    ///
    /// On a real in-place change it persists the new body into the
    /// content-addressed table and **advances the baseline** to the new
    /// `(path, hash)` so the same change is injected exactly once; the next
    /// request diffs from the just-injected version.
    pub async fn guidance_change_injection(&self, cwd: &std::path::Path) -> Option<String> {
        let baseline = match self.db.guidance_baseline(self.id).await {
            Ok(Some(b)) => b,
            // No baseline stored → feature inert for this session.
            Ok(None) => return None,
            Err(e) => {
                tracing::warn!(error = %e, "guidance diff: reading baseline failed");
                return None;
            }
        };

        // Re-resolve the currently-winning guidance file. Deleted → None;
        // switched → a different path. Both are out of scope.
        let (current_path, current_body) = crate::engine::builtin::load_agent_guidance(cwd)?;
        let current_path = current_path.display().to_string();
        if current_path != baseline.path {
            // File deleted or a different file now wins — no in-place
            // change to track. Leave the baseline as-is; do not inject.
            return None;
        }

        let current_hash = crate::engine::guidance_diff::hash_contents(&current_body);
        if current_hash == baseline.hash {
            // Unchanged since baseline — idempotent no-op.
            return None;
        }

        // A genuine in-place edit. Persist the new body (content-addressed,
        // idempotent) and build the injection from the prior stored body.
        if let Err(e) = self
            .db
            .put_guidance_contents(&current_hash, &current_body)
            .await
        {
            tracing::warn!(error = %e, "guidance diff: storing new contents failed");
            return None;
        }
        let prior = self
            .db
            .guidance_contents(&baseline.hash)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "guidance diff: reading prior contents failed");
                None
            });
        let injection =
            crate::engine::guidance_diff::decide_injection(prior.as_deref(), &current_body);
        let message = crate::engine::guidance_diff::injection_message(&current_path, &injection);

        // Advance the baseline so this change injects exactly once.
        let advanced = crate::db::guidance::GuidanceBaseline {
            path: current_path,
            hash: current_hash,
        };
        if let Err(e) = self
            .db
            .set_guidance_baseline(self.id, Some(&advanced))
            .await
        {
            tracing::warn!(error = %e, "guidance diff: advancing baseline failed");
            // Returning the message anyway would risk re-injecting the same
            // change next turn (baseline not advanced). Skip this injection
            // rather than risk a loop.
            return None;
        }
        Some(message)
    }

    /// Append one event to the session timeline (session-log-export Part
    /// B). Always-on, engine/daemon-owned. Returns the assigned monotonic
    /// `seq`. Best-effort callers may ignore the result.
    pub async fn record_event(
        &self,
        kind: crate::db::session_log::SessionEventKind,
        agent: Option<&str>,
        call_id: Option<&str>,
        data: &Value,
    ) -> Result<i64> {
        self.record_event_with_origin(kind, agent, call_id, None, data)
            .await
    }

    pub async fn record_event_with_origin(
        &self,
        kind: crate::db::session_log::SessionEventKind,
        agent: Option<&str>,
        call_id: Option<&str>,
        origin_principal: Option<&str>,
        data: &Value,
    ) -> Result<i64> {
        self.record_event_with_origin_and_frame(kind, agent, call_id, origin_principal, None, data)
            .await
    }

    pub async fn record_terminal_client_submissions(
        &self,
        receipts: &[crate::engine::message::ClientSubmissionReceipt],
        disposition: crate::db::session_log::ClientSubmissionTerminalDisposition,
    ) -> Result<()> {
        let receipts = receipts
            .iter()
            .map(
                |receipt| crate::db::session_log::ClientSubmissionTerminalReceipt {
                    client_submission_id: receipt.id,
                    fingerprint: receipt.fingerprint.clone(),
                    wire_fingerprint: receipt.wire_fingerprint.clone(),
                    origin_principal: receipt.origin_principal.clone(),
                    disposition,
                },
            )
            .collect();
        self.db
            .insert_client_submission_terminal_receipts(self.id, receipts)
            .await
    }

    async fn record_event_with_origin_and_frame(
        &self,
        kind: crate::db::session_log::SessionEventKind,
        agent: Option<&str>,
        call_id: Option<&str>,
        origin_principal: Option<&str>,
        frame: Option<SessionEventModelFrame<'_>>,
        data: &Value,
    ) -> Result<i64> {
        let lineage = current_session_event_lineage();
        let provenance = self.session_event_provenance_for(kind, frame, data);
        let provenance_fields = provenance
            .as_ref()
            .map(SessionEventProvenance::context_fields);
        let context = crate::db::session_log::SessionEventContext {
            origin_principal,
            task_call_id: lineage.as_ref().map(|l| l.task_call_id.as_str()),
            label: lineage.as_ref().map(|l| l.label.as_str()),
            provider_id: provenance_fields.map(|fields| fields.0),
            model_id: provenance_fields.map(|fields| fields.1),
            llm_mode: provenance_fields.map(|fields| fields.2),
            model_trust: provenance_fields.map(|fields| fields.3),
        };

        // A trusted, model-authored event journals its table-matched literals in
        // the same transaction as the event row (decision 10.3). Non-model-
        // authored events (provenance `None`), untrusted model-authored events
        // (payload already post-redaction), and scratch sessions persist as
        // today with no journaling.
        let trusted_model_authored = provenance.as_ref().is_some_and(|p| {
            matches!(p.model_trust, crate::config::providers::ModelTrust::Trusted)
        });
        if trusted_model_authored
            && !self.unjournaled_inference_allowed()
            && let Some(frame) = frame
        {
            return self
                .record_trusted_event_journaled(
                    kind,
                    agent,
                    call_id,
                    context,
                    frame.session_table,
                    data,
                )
                .await;
        }

        self.db
            .insert_session_event_with_context(self.id, kind, agent, call_id, context, data)
            .await
            .context("inserting session_event")
    }

    /// Compose a trusted model-authored event row and its protected-history
    /// journal in one transaction (decision 10.3). Off the DB thread we scan the
    /// serialized `data` against the pre-policy session table and `prepare_append`
    /// each match; any prepare failure fails closed (decision 12) to a redacted
    /// event body with no history rows. Otherwise the event row is written via the
    /// existing conn-scoped [`Db::insert_session_event_json_conn`] to obtain its
    /// `seq`, then every prepared append is attached to that `seq` — all committed
    /// together or rolled back together.
    async fn record_trusted_event_journaled(
        &self,
        kind: crate::db::session_log::SessionEventKind,
        agent: Option<&str>,
        call_id: Option<&str>,
        context: crate::db::session_log::SessionEventContext<'_>,
        session_table: &crate::redact::RedactionTable,
        data: &Value,
    ) -> Result<i64> {
        // JSON-value-aware match (F2): scan each DECODED string in the event
        // body, not the escaped serialized blob.
        let matches = match_literals_in_json(session_table, data);
        if matches.is_empty() {
            return self
                .db
                .insert_session_event_with_context(self.id, kind, agent, call_id, context, data)
                .await
                .context("inserting session_event");
        }
        let data_json = serde_json::to_string(data).context("serializing event data")?;

        let resolver = self.redaction_key_resolver().clone();
        let history = crate::redact::protected_redaction_history::ProtectedRedactionHistory::new(
            &self.db,
            resolver.as_ref(),
        );
        let session_id_str = self.id.to_string();
        let mut prepared = Vec::with_capacity(matches.len());
        for m in &matches {
            let literal = match matched_to_protected_literal(m) {
                Ok(literal) => literal,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "trusted event journaling: literal rejected; persisting redacted event"
                    );
                    return self
                        .persist_redacted_event(kind, agent, call_id, context, data, session_table)
                        .await;
                }
            };
            match history.prepare_append(&session_id_str, literal).await {
                Ok(p) => prepared.push(p),
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "trusted event journaling: prepare_append failed; persisting redacted event"
                    );
                    return self
                        .persist_redacted_event(kind, agent, call_id, context, data, session_table)
                        .await;
                }
            }
        }

        let artifact_kind = event_artifact_kind(kind);
        let session_id = self.id;
        // Owned copies for the `move` closure. Named distinctly so the original
        // borrowed `agent`/`call_id`/`context` params stay available for the
        // decision-12 fallback below (F1).
        let agent_owned = agent.map(str::to_owned);
        let call_id_owned = call_id.map(str::to_owned);
        let task_call_id = context.task_call_id.map(str::to_owned);
        let label = context.label.map(str::to_owned);
        let origin_principal = context.origin_principal.map(str::to_owned);
        let provider_id = context.provider_id.map(str::to_owned);
        let model_id = context.model_id.map(str::to_owned);
        let llm_mode = context.llm_mode.map(str::to_owned);
        let model_trust = context.model_trust.map(str::to_owned);
        let ts_ms = crate::db::session_log::now_ms();
        let journal_result = self
            .db
            .transaction(move |conn| {
                let seq = Db::insert_session_event_json_conn(
                    conn,
                    session_id,
                    kind,
                    agent_owned.as_deref(),
                    call_id_owned.as_deref(),
                    crate::db::session_log::SessionEventContext {
                        origin_principal: origin_principal.as_deref(),
                        task_call_id: task_call_id.as_deref(),
                        label: label.as_deref(),
                        provider_id: provider_id.as_deref(),
                        model_id: model_id.as_deref(),
                        llm_mode: llm_mode.as_deref(),
                        model_trust: model_trust.as_deref(),
                    },
                    ts_ms,
                    &data_json,
                )?;
                // Mid-transaction failure seam (AC9): force an error after the
                // event row write and before the journal attach.
                #[cfg(test)]
                if journal_fault::should_fail_after_artifact_row() {
                    anyhow::bail!("injected mid-transaction event journal fault (test seam)");
                }
                let refs = [
                    crate::redact::protected_redaction_history::ArtifactRef::new(
                        artifact_kind,
                        seq.to_string(),
                    ),
                ];
                for prepared in &prepared {
                    crate::redact::protected_redaction_history::append_and_attach_conn(
                        conn, prepared, &refs,
                    )?;
                }
                Ok(seq)
            })
            .await;

        // Decision-12 fail-closed for a journal-TRANSACTION failure (F1): the
        // event row + history/refs roll back together ATOMICALLY (AC9), THEN the
        // matched-literal-scrubbed event body is persisted via a separate
        // non-journaling insert (no history); the turn is not aborted.
        match journal_result {
            Ok(seq) => Ok(seq),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "trusted event journaling: transaction failed; persisting redacted event"
                );
                self.persist_redacted_event(kind, agent, call_id, context, data, session_table)
                    .await
            }
        }
    }

    /// Fail-closed event persistence (decision 12): scrub every table literal
    /// WITHIN the parsed JSON string values/keys/scalar leaves with the table's
    /// overlap-safe production scrub (F2 escape-safe), then persist the
    /// re-serialized body through the normal insert with NO history rows.
    async fn persist_redacted_event(
        &self,
        kind: crate::db::session_log::SessionEventKind,
        agent: Option<&str>,
        call_id: Option<&str>,
        context: crate::db::session_log::SessionEventContext<'_>,
        data: &Value,
        session_table: &crate::redact::RedactionTable,
    ) -> Result<i64> {
        let redacted = scrub_body_fail_closed(data, session_table);
        self.db
            .insert_session_event_with_context(self.id, kind, agent, call_id, context, &redacted)
            .await
            .context("inserting redacted session_event")
    }

    /// Record a durable user-visible notice. Notice emit sites stay UI-facing;
    /// this helper is the single writer that makes the notice exportable.
    pub async fn record_notice(
        &self,
        agent: Option<&str>,
        text: &str,
        source: &str,
    ) -> Result<i64> {
        self.record_event(
            crate::db::session_log::SessionEventKind::Notice,
            agent,
            None,
            &serde_json::json!({
                "text": text,
                "severity": notice_severity(text),
                "source": source,
            }),
        )
        .await
    }

    /// Record a `context_pruned` timeline event (session-log-export Part
    /// C). Fired by the real `/prune` path (manual + cache-cold auto): a
    /// wire-only snapshot dedup that elided superseded tool-result bodies.
    /// Carries messages-before/after, wire tokens-before/after, the elided
    /// `original_event_id`s, the reason, and the trigger (auto vs manual).
    ///
    /// Because auto-prune fires right before an inference call, this event
    /// lands immediately before the next `inference_request` event in
    /// `seq` order — the two adjacent request payloads then *show* the
    /// elision directly, which is the before/after-prune audit the export
    /// is for. `agent` is the foreground agent the prune targeted.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_context_pruned(
        &self,
        agent: &str,
        auto: bool,
        messages_before: usize,
        messages_after: usize,
        tokens_before: u64,
        tokens_after: u64,
        elided: &[String],
        reason: &str,
        tokens_saved: u64,
        remaining_budget: Option<u64>,
        trigger_reason: Option<&str>,
    ) -> Result<i64> {
        self.record_event(
            crate::db::session_log::SessionEventKind::ContextPruned,
            Some(agent),
            None,
            &serde_json::json!({
                "kind": "prune",
                "trigger": if auto { "auto" } else { "manual" },
                "messages_before": messages_before,
                "messages_after": messages_after,
                "tokens_before": tokens_before,
                "tokens_after": tokens_after,
                // The projected cl100k_base wire saving this prune realized,
                // so `analyze-session-logs` can judge effectiveness without
                // re-diffing the adjacent request payloads.
                "tokens_saved": tokens_saved,
                // Remaining context budget (model window − post-prune input
                // tokens) when the window + last usage are known; `null`
                // otherwise (ctx%-gated metrics inert).
                "remaining_budget": remaining_budget,
                "elided": elided,
                // Present for auto-prune so exports show why it fired
                // (cold cache, no-cache provider, upstream bust, or the warm
                // ctx/prunable threshold branch). Manual `/prune` leaves it
                // null because the trigger is the user command.
                "trigger_reason": trigger_reason,
                // The classifying reason: `overlap-merge`, `exact-identity`,
                // or `mixed` — distinct from the escalation-to-compaction
                // path, which records a `session_compacted` boundary instead.
                "reason": reason,
            }),
        )
        .await
    }

    /// Record a `session_compacted` timeline boundary (session-log-export
    /// Part C). `/compact` is a fresh-thread handoff, not an in-session
    /// edit: it starts a brand-new successor session and preserves this
    /// one. Modeled as a session boundary (predecessor → successor short
    /// ids) the export follows like the fork tree, so both sessions land
    /// in one unified `events.json`. Not a `context_pruned` event.
    #[allow(dead_code)]
    pub async fn record_session_compacted(
        &self,
        agent: &str,
        successor_session_id: Uuid,
        successor_short_id: &str,
        seed_tool_count: usize,
        brief_text: &str,
    ) -> Result<i64> {
        self.record_session_compacted_with_source(
            agent,
            SessionCompactionRecord {
                successor_session_id,
                successor_short_id,
                seed_tool_count,
                brief_text,
                handoff_text: brief_text,
                source: "manual",
                trigger_ctx_pct: None,
                tokens_before: 0,
                tokens_after: 0,
                turns_summarized: 0,
                tail_kept: 0,
                tail_trimmed: 0,
                tail_messages: &[],
            },
            None,
        )
        .await
    }

    /// Record a `session_compacted` boundary. The record embeds model-authored
    /// content (`brief_text` / `handoff_text` drafted by the compaction model,
    /// plus the retained assistant-tail messages), so when `frame` names a
    /// TRUSTED authoring model this routes through the frame-carrying journaling
    /// path (decision 10.3): a session-table literal in that content journals to
    /// protected redaction history (or fail-closed scrubs) instead of persisting
    /// raw with no history row (K1). The oversize offload to `compaction_handoffs`
    /// is journaled the same way so a matched literal is never stored raw there
    /// either. `frame` is threaded from the production caller
    /// (`apply_prepared_compaction`) as the drafting model's identity; a
    /// frame-less / untrusted author, and a scratch session, journal nothing.
    pub async fn record_session_compacted_with_source(
        &self,
        agent: &str,
        record: SessionCompactionRecord<'_>,
        frame: Option<SessionEventModelFrame<'_>>,
    ) -> Result<i64> {
        const INLINE_HANDOFF_MAX_BYTES: usize = 16 * 1024;
        let data = serde_json::json!({
            "kind": "compaction",
            "predecessor_session_id": self.id.to_string(),
            "predecessor_short_id": self.short_id,
            "successor_session_id": record.successor_session_id.to_string(),
            "successor_short_id": record.successor_short_id,
            "seed_tool_count": record.seed_tool_count,
            "brief_text": record.brief_text,
            "handoff_text": record.handoff_text,
            "source": record.source,
            "trigger_ctx_pct": record.trigger_ctx_pct,
            "tokens_before": record.tokens_before,
            "tokens_after": record.tokens_after,
            "turns_summarized": record.turns_summarized,
            "tail_kept": record.tail_kept,
            "tail_trimmed": record.tail_trimmed,
            "tail_messages": record.tail_messages,
        });
        if data.to_string().len() > INLINE_HANDOFF_MAX_BYTES {
            let handoff_id = Uuid::new_v4();
            // The full model-authored payload is offloaded to
            // `compaction_handoffs`; journal (or fail-closed scrub) its trusted
            // table-matched literals so none is stored raw there (K1).
            self.store_compaction_payload_journaled(handoff_id, &data, frame)
                .await?;
            let trimmed = serde_json::json!({
                "kind": "compaction",
                "predecessor_session_id": self.id.to_string(),
                "predecessor_short_id": self.short_id,
                "successor_session_id": record.successor_session_id.to_string(),
                "successor_short_id": record.successor_short_id,
                "seed_tool_count": record.seed_tool_count,
                "source": record.source,
                "trigger_ctx_pct": record.trigger_ctx_pct,
                "tokens_before": record.tokens_before,
                "tokens_after": record.tokens_after,
                "turns_summarized": record.turns_summarized,
                "tail_kept": record.tail_kept,
                "tail_trimmed": record.tail_trimmed,
                "handoff_ref": handoff_id.to_string(),
            });
            // The trimmed event body carries only metadata + `handoff_ref` (no
            // brief/handoff/tail), so its own frame scan matches nothing; still
            // route it through the frame path for provenance/trust consistency.
            return self
                .record_event_with_origin_and_frame(
                    crate::db::session_log::SessionEventKind::SessionCompacted,
                    Some(agent),
                    None,
                    None,
                    frame,
                    &trimmed,
                )
                .await;
        }
        // Inline: the event body carries the full model-authored record, so the
        // frame path journals its trusted table-matched literals against the
        // committed event `seq` (or fail-closed scrubs the body).
        self.record_event_with_origin_and_frame(
            crate::db::session_log::SessionEventKind::SessionCompacted,
            Some(agent),
            None,
            None,
            frame,
            &data,
        )
        .await
    }

    /// Persist an oversize compaction payload to `compaction_handoffs`,
    /// journaling its TRUSTED table-matched literals to protected redaction
    /// history in the SAME transaction as the payload write (K1, decision
    /// 10.3/12). A frame-less / untrusted author (payload post-redaction) and a
    /// scratch session store the payload raw with no journaling. On any journal
    /// failure we fail closed: the matched-literal-scrubbed payload is stored
    /// instead (decision 12), the turn is not aborted.
    async fn store_compaction_payload_journaled(
        &self,
        handoff_id: Uuid,
        data: &Value,
        frame: Option<SessionEventModelFrame<'_>>,
    ) -> Result<()> {
        // Journal only for a trusted authoring model that has not opted out.
        let session_table = frame.and_then(|frame| {
            let snapshot = frame.config.snapshot();
            matches!(
                snapshot
                    .providers
                    .resolve_trust(frame.provider_id, frame.model_id),
                crate::config::providers::ModelTrust::Trusted
            )
            .then_some(frame.session_table)
        });
        let Some(session_table) = session_table.filter(|_| !self.unjournaled_inference_allowed())
        else {
            return self
                .db
                .store_compaction_payload(handoff_id, self.id, &data.to_string())
                .await;
        };

        // JSON-value-aware match (F2) over the full offloaded record.
        let matches = match_literals_in_json(session_table, data);
        if matches.is_empty() {
            return self
                .db
                .store_compaction_payload(handoff_id, self.id, &data.to_string())
                .await;
        }
        let payload_json =
            serde_json::to_string(data).context("serializing compaction payload for journaling")?;

        let resolver = self.redaction_key_resolver().clone();
        let history = crate::redact::protected_redaction_history::ProtectedRedactionHistory::new(
            &self.db,
            resolver.as_ref(),
        );
        let session_id_str = self.id.to_string();
        let mut prepared = Vec::with_capacity(matches.len());
        for m in &matches {
            let literal = match matched_to_protected_literal(m) {
                Ok(literal) => literal,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "compaction journaling: literal rejected; storing redacted payload"
                    );
                    return self
                        .store_compaction_payload_redacted(handoff_id, data, session_table)
                        .await;
                }
            };
            match history.prepare_append(&session_id_str, literal).await {
                Ok(p) => prepared.push(p),
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "compaction journaling: prepare_append failed; storing redacted payload"
                    );
                    return self
                        .store_compaction_payload_redacted(handoff_id, data, session_table)
                        .await;
                }
            }
        }

        let session_id = self.id;
        let refs = [
            crate::redact::protected_redaction_history::ArtifactRef::new(
                crate::redact::protected_redaction_history::RedactionArtifactKind::Event,
                handoff_id.to_string(),
            ),
        ];
        let journal_result = self
            .db
            .transaction(move |conn| {
                Db::store_compaction_payload_conn(conn, handoff_id, session_id, &payload_json)?;
                // Mid-transaction failure seam (AC9): force an error after the
                // payload-row write and before the journal attach.
                #[cfg(test)]
                if journal_fault::should_fail_after_artifact_row() {
                    anyhow::bail!("injected mid-transaction compaction journal fault (test seam)");
                }
                for prepared in &prepared {
                    crate::redact::protected_redaction_history::append_and_attach_conn(
                        conn, prepared, &refs,
                    )?;
                }
                Ok(())
            })
            .await;

        // Decision-12 fail-closed for a journal-TRANSACTION failure (F1): the
        // payload row + history/refs roll back together ATOMICALLY, THEN the
        // matched-literal-scrubbed payload is stored via a separate write (no
        // history); the turn is not aborted.
        if let Err(e) = journal_result {
            tracing::warn!(
                error = %e,
                "compaction journaling: transaction failed; storing redacted payload"
            );
            return self
                .store_compaction_payload_redacted(handoff_id, data, session_table)
                .await;
        }
        Ok(())
    }

    /// Fail-closed compaction-payload store (decision 12): scrub every table
    /// literal within the parsed payload with the table's overlap-safe
    /// production scrub, then store the re-serialized body with no history rows.
    async fn store_compaction_payload_redacted(
        &self,
        handoff_id: Uuid,
        data: &Value,
        session_table: &crate::redact::RedactionTable,
    ) -> Result<()> {
        let redacted = scrub_body_fail_closed(data, session_table);
        self.db
            .store_compaction_payload(handoff_id, self.id, &redacted.to_string())
            .await
    }

    /// Record a `tool_rejected` timeline event (export-audit fidelity). Fired
    /// from the dispatcher's validate-then-repair path (GOALS §12) when a call
    /// is rejected **before** it becomes a `tool_call` row — a hallucinated
    /// tool name (`not_in_advertised_set`), an unrepairable malformed call
    /// (`schema_invalid_unrepairable`), or a path-field pointing at a
    /// nonexistent file (`path_not_found`, model path-hallucination). Carries
    /// the attempted tool `name`, the `reason`, and optionally a compact
    /// corrected-shape hint when the dispatcher emitted one (token economy,
    /// project guidance priority #2): a hallucinated / unrepairable call becomes a
    /// one-query check instead of prose inference.
    /// The `call_id` is the model's per-tool-call id so the rejection joins the
    /// assistant turn that emitted it.
    pub async fn record_tool_rejected(
        &self,
        agent: &str,
        call_id: &str,
        tool: &str,
        reason: &str,
    ) -> Result<i64> {
        self.record_tool_rejected_with_correction(agent, call_id, tool, reason, None)
            .await
    }

    pub async fn record_tool_rejected_with_correction(
        &self,
        agent: &str,
        call_id: &str,
        tool: &str,
        reason: &str,
        correction: Option<Value>,
    ) -> Result<i64> {
        let mut data = serde_json::json!({
            "tool": tool,
            "reason": reason,
        });
        if let Some(correction) = correction {
            data["validation_correction"] = correction;
        }
        // Host-authored rejection record: `tool` and `reason` are host constants
        // (e.g. `task_unknown_agent`), and no production caller passes a
        // `correction` — the two live call sites (engine/agent/turn_phases.rs) use
        // the `record_tool_rejected` wrapper with `None`. So this ToolRejected
        // payload carries no model-authored session-table literal. Frame-less
        // `record_event` is correct; nothing to journal. (Should a future caller
        // supply a model-derived `correction`, route this through the framed path
        // like tool_dispatch.rs.)
        self.record_event(
            crate::db::session_log::SessionEventKind::ToolRejected,
            Some(agent),
            Some(call_id),
            &data,
        )
        .await
    }

    /// Record a `primary_swap` timeline event (export-audit fidelity). Fired
    /// whenever the root-frame primary is re-rooted (GOALS §26): live
    /// `/plan`/`/build` slash-command swaps use trigger `swap_command`.
    /// Historical sessions may also carry trigger `handoff` from the retired
    /// native handoff tool. Preserves the wire-vs-user split (GOALS §14):
    /// `display` is the user-facing row and `kickoff` is the model-facing wire
    /// kickoff. Live slash-command swaps inject no kickoff, so `kickoff` is
    /// absent there (`None`) — never fabricated. Carries only
    /// `from`/`to`/`trigger`/`display`/`kickoff` (token economy, project
    /// guidance priority #2).
    pub async fn record_primary_swap(
        &self,
        from: &str,
        to: &str,
        trigger: &str,
        display: Option<&str>,
        kickoff: Option<&str>,
    ) -> Result<i64> {
        // Host/template-authored: `from`/`to` are agent names, `trigger` is a closed
        // enum string, and `display`/`kickoff` are the host-composed swap row and
        // (for a `/build`-style swap) the host kickoff prompt — not model-authored
        // free text. So this PrimarySwap payload carries no model session-table
        // literal; frame-less `record_event` is correct, nothing to journal.
        self.record_event(
            crate::db::session_log::SessionEventKind::PrimarySwap,
            Some(from),
            None,
            &serde_json::json!({
                "from": from,
                "to": to,
                "trigger": trigger,
                "display": display,
                "kickoff": kickoff,
            }),
        )
        .await
    }

    /// Record a `model_switch` timeline event for every active-model switch
    /// attempt, including no-ops and failures. Carries only provider/model
    /// ids, the closed trigger/outcome strings, and the real error text when
    /// one exists; the shared session-event redaction path handles payload
    /// scrubbing before export.
    pub async fn record_model_switch(&self, audit: ModelSwitchAudit<'_>) -> Result<i64> {
        self.record_event(
            crate::db::session_log::SessionEventKind::ModelSwitch,
            None,
            None,
            &serde_json::json!({
                "from_provider": audit.from_provider,
                "from_model": audit.from_model,
                "to_provider": audit.to_provider,
                "to_model": audit.to_model,
                "trigger": audit.trigger.as_str(),
                "outcome": audit.outcome.as_str(),
                "error": audit.error,
            }),
        )
        .await
    }

    /// Most recent provider-reported usage, if we've made any calls
    /// this session. Returns `None` before the first round-trip
    /// finishes — callers fall back to a local tiktoken estimate.
    pub fn last_usage(&self) -> Option<crate::tokens::TokenUsage> {
        *self.last_usage.lock().unwrap()
    }

    /// Seed the in-memory `last_usage` **without** writing an
    /// `inference_calls` row. Used by resume rehydration
    /// (implementation note) to recompute the context
    /// indicator from the reconstructed pruned history before the provider
    /// reports a real count — a local estimate, not a real round-trip, so
    /// it must not pollute `/stats`. The next real `record_usage` overwrites
    /// it with the provider's figure.
    pub fn set_last_usage_estimate(&self, usage: crate::tokens::TokenUsage) {
        *self.last_usage.lock().unwrap() = Some(usage);
    }
}

pub(crate) fn notice_severity(text: &str) -> &'static str {
    let lower = text.to_ascii_lowercase();
    if lower.contains("failed")
        || lower.contains("failure")
        || lower.contains("error")
        || lower.contains("denied")
        || lower.contains("rejected")
    {
        "failure"
    } else if lower.contains("warning")
        || lower.contains("warn")
        || lower.contains("unsupported")
        || lower.contains("repair required")
        || lower.contains("missing")
    {
        "warning"
    } else {
        "info"
    }
}

#[cfg(test)]
mod notice_tests {
    use super::*;
    use crate::db::Db;

    #[tokio::test]
    async fn notice_records_typed_severity_and_source() {
        let db = Db::open_in_memory().unwrap();
        let session = Session::create(
            db,
            std::path::PathBuf::from("/proj"),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();

        session
            .record_notice(
                Some("Build"),
                "Resume repair required before continuing.",
                "daemon_direct",
            )
            .await
            .unwrap();

        let events = session.db.list_session_events(session.id).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "notice");
        assert_eq!(events[0].agent.as_deref(), Some("Build"));
        assert_eq!(
            events[0].data["text"],
            "Resume repair required before continuing."
        );
        assert_eq!(events[0].data["severity"], "warning");
        assert_eq!(events[0].data["source"], "daemon_direct");
    }

    #[tokio::test]
    async fn unclassified_notice_defaults_to_info_and_is_not_dropped() {
        let db = Db::open_in_memory().unwrap();
        let session = Session::create(
            db,
            std::path::PathBuf::from("/proj"),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();

        session
            .record_notice(None, "Background refresh finished.", "engine_turn")
            .await
            .unwrap();

        let events = session.db.list_session_events(session.id).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data["severity"], "info");
        assert_eq!(events[0].data["source"], "engine_turn");
    }
}

#[cfg(test)]
mod session_event_provenance_tests {
    use super::*;
    use crate::db::Db;
    use serde_json::json;
    use std::path::Path;

    fn write_provider(root: &Path, provider: &str, model: &str, trust: &str, mode: &str) {
        let cockpit = root.join(".cockpit");
        let providers = cockpit.join("providers");
        std::fs::create_dir_all(&providers).unwrap();
        std::fs::write(cockpit.join("config.json"), r#"{"llm_mode":"defensive"}"#).unwrap();
        std::fs::write(
            providers.join(format!("{provider}.json")),
            serde_json::json!({
                "url": "https://example.test/v1",
                "models": [{
                    "id": model,
                    "trust": trust,
                    "mode": mode,
                }],
            })
            .to_string(),
        )
        .unwrap();
    }

    #[tokio::test]
    async fn session_event_provenance_stamps_model_authored_and_model_less_rows() {
        let tmp = tempfile::tempdir().unwrap();
        write_provider(tmp.path(), "openai", "gpt-5", "trusted", "frontier");
        let db = Db::open_in_memory().unwrap();
        let session = Session::create(
            db,
            tmp.path().to_path_buf(),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        session.set_active_model("openai", "gpt-5").unwrap();
        let config =
            crate::daemon::session_worker::SessionConfigHandle::from_disk_for_tests(tmp.path());

        let session_table = crate::redact::RedactionTable::empty();
        session
            .record_event_with_model_frame(
                crate::db::session_log::SessionEventKind::AssistantMessage,
                Some("Build"),
                Some("call-1"),
                SessionEventModelFrame {
                    provider_id: "openai",
                    model_id: "gpt-5",
                    config: &config,
                    session_table: &session_table,
                },
                &json!({"text": "model text"}),
            )
            .await
            .unwrap();
        session
            .record_event(
                crate::db::session_log::SessionEventKind::UserMessage,
                Some("Build"),
                None,
                &json!({"text": "user text"}),
            )
            .await
            .unwrap();
        session
            .record_notice(Some("Build"), "Background refresh finished.", "engine")
            .await
            .unwrap();

        let events = session.db.list_session_events(session.id).await.unwrap();
        assert_eq!(events[0].provider_id.as_deref(), Some("openai"));
        assert_eq!(events[0].model_id.as_deref(), Some("gpt-5"));
        assert_eq!(events[0].llm_mode.as_deref(), Some("frontier"));
        assert_eq!(events[0].model_trust.as_deref(), Some("trusted"));
        for event in &events[1..] {
            assert_eq!(event.provider_id, None);
            assert_eq!(event.model_id, None);
            assert_eq!(event.llm_mode, None);
            assert_eq!(event.model_trust, None);
        }
    }

    #[tokio::test]
    async fn session_event_provenance_prefers_event_frame_model_over_root_model() {
        let tmp = tempfile::tempdir().unwrap();
        write_provider(tmp.path(), "root", "root-model", "untrusted", "defensive");
        write_provider(tmp.path(), "child", "child-model", "trusted", "normal");
        let db = Db::open_in_memory().unwrap();
        let session = Session::create(
            db,
            tmp.path().to_path_buf(),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        session.set_active_model("root", "root-model").unwrap();
        let config =
            crate::daemon::session_worker::SessionConfigHandle::from_disk_for_tests(tmp.path());

        session
            .record_event_with_config(
                crate::db::session_log::SessionEventKind::SubagentRouting,
                Some("history"),
                Some("task-1"),
                &config,
                &crate::redact::RedactionTable::empty(),
                &json!({
                    "child_agent": "history",
                    "task_call_id": "task-1",
                    "label": "default",
                    "provider": "child",
                    "model": "child-model",
                }),
            )
            .await
            .unwrap();

        let event = session
            .db
            .list_session_events(session.id)
            .await
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(event.provider_id.as_deref(), Some("child"));
        assert_eq!(event.model_id.as_deref(), Some("child-model"));
        assert_eq!(event.llm_mode.as_deref(), Some("normal"));
        assert_eq!(event.model_trust.as_deref(), Some("trusted"));
    }

    #[tokio::test]
    async fn session_event_provenance_materializes_trust_at_write_time() {
        let tmp = tempfile::tempdir().unwrap();
        write_provider(tmp.path(), "openai", "gpt-5", "trusted", "frontier");
        let db = Db::open_in_memory().unwrap();
        let session = Session::create(
            db,
            tmp.path().to_path_buf(),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        session.set_active_model("openai", "gpt-5").unwrap();
        let config =
            crate::daemon::session_worker::SessionConfigHandle::from_disk_for_tests(tmp.path());

        let session_table = crate::redact::RedactionTable::empty();
        session
            .record_event_with_model_frame(
                crate::db::session_log::SessionEventKind::AssistantMessage,
                Some("Build"),
                None,
                SessionEventModelFrame {
                    provider_id: "openai",
                    model_id: "gpt-5",
                    config: &config,
                    session_table: &session_table,
                },
                &json!({"text": "before config change"}),
            )
            .await
            .unwrap();
        write_provider(tmp.path(), "openai", "gpt-5", "untrusted", "defensive");

        let event = session
            .db
            .list_session_events(session.id)
            .await
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(event.model_trust.as_deref(), Some("trusted"));
        assert_eq!(event.llm_mode.as_deref(), Some("frontier"));
    }
}

/// Trusted-ingress journaling acceptance tests (AC9/AC10/AC11): every test drives
/// a production recording chokepoint (`record_inference_request` /
/// `record_event_with_model_frame`) — never a parallel reimplementation — and
/// reads the durable protected-history rows/refs back through the db API.
#[cfg(test)]
mod trusted_journaling_tests {
    use super::*;
    use crate::db::Db;
    use crate::db::session_log::{InferencePhaseTimings, InferenceRequestStatus, SessionEventKind};
    use crate::redact::RedactionTable;
    use crate::redact::protected_redaction_history::{
        RedactionArtifactKind, RedactionHistorySource,
    };
    use std::path::{Path, PathBuf};
    use uuid::Uuid;

    const ENV_LIT: &str = "env-scan-secret-abc123456";
    const CRED_LIT: &str = "stored-credential-secret-xyz789";

    fn redact_cfg() -> crate::config::extended::RedactConfig {
        crate::config::extended::RedactConfig {
            enabled: true,
            scan_environment: true,
            scan_dotenv: false,
            scan_ssh_keys: false,
            min_secret_length: 4,
            placeholder: "[redacted]".to_string(),
            ..crate::config::extended::RedactConfig::default()
        }
    }

    /// A real pre-policy session table built through the production seams with one
    /// `Environment` entry (env scan) and one `Credential` entry (stored secret).
    fn env_credential_table() -> RedactionTable {
        let env =
            std::collections::HashMap::from([("DEPLOY_TOKEN".to_string(), ENV_LIT.to_string())]);
        RedactionTable::build_with_env_and_secrets(
            &redact_cfg(),
            Path::new("."),
            &env,
            [("stored_api".to_string(), CRED_LIT.to_string())],
        )
        .unwrap()
    }

    /// A table carrying a single `Environment` literal `lit`.
    fn env_only_table(lit: &str) -> RedactionTable {
        let env = std::collections::HashMap::from([("DEPLOY_TOKEN".to_string(), lit.to_string())]);
        RedactionTable::build_with_env(&redact_cfg(), Path::new("."), &env).unwrap()
    }

    fn write_trusted_provider(root: &Path) {
        let cockpit = root.join(".cockpit");
        let providers = cockpit.join("providers");
        std::fs::create_dir_all(&providers).unwrap();
        std::fs::write(cockpit.join("config.json"), r#"{"llm_mode":"defensive"}"#).unwrap();
        std::fs::write(
            providers.join("openai.json"),
            serde_json::json!({
                "url": "https://example.test/v1",
                "models": [{"id": "gpt-5", "trust": "trusted", "mode": "frontier"}],
            })
            .to_string(),
        )
        .unwrap();
    }

    fn new_session(db: Db) -> Session {
        Session::create(
            db,
            PathBuf::from("/proj"),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap()
    }

    // -- AC9 -----------------------------------------------------------------

    #[tokio::test]
    async fn trusted_request_persistence_journals_matched_literals_atomically() {
        let db = Db::open_in_memory().unwrap();
        let session = new_session(db.clone());
        let table = env_credential_table();
        let call_id = Uuid::new_v4();
        let payload = serde_json::json!({
            "messages": [{"role": "user", "content": format!("deploy {ENV_LIT} using {CRED_LIT}")}],
        });

        session
            .record_inference_request(
                call_id,
                &payload,
                InferenceRequestStatus::Completed,
                &table,
                true,
            )
            .await
            .unwrap();

        // Both matched literals journal, with their typed sources.
        let sid = session.id.to_string();
        let rows = db.protected_redaction_history_list(&sid).await.unwrap();
        assert_eq!(rows.len(), 2, "env + credential both journaled: {rows:#?}");
        let sources: std::collections::HashSet<_> = rows.iter().map(|r| r.source).collect();
        assert!(sources.contains(&RedactionHistorySource::Environment));
        assert!(sources.contains(&RedactionHistorySource::Credential));

        // Refs: one Request (= call_id) and one Attempt (= `{call_id}_o0`) per row.
        let req_refs = db
            .protected_redaction_artifact_refs_for_artifact(
                RedactionArtifactKind::Request,
                &call_id.to_string(),
            )
            .await
            .unwrap();
        assert_eq!(req_refs.len(), 2, "one Request ref per journaled literal");
        let attempt_refs = db
            .protected_redaction_artifact_refs_for_artifact(
                RedactionArtifactKind::Attempt,
                &format!("{call_id}_o0"),
            )
            .await
            .unwrap();
        assert_eq!(
            attempt_refs.len(),
            2,
            "one Attempt ref per journaled literal"
        );

        // A status-only advance never re-journals.
        session
            .advance_inference_request(
                call_id,
                0,
                InferenceRequestStatus::Completed,
                InferencePhaseTimings::default(),
            )
            .await
            .unwrap();
        assert_eq!(
            db.protected_redaction_history_list(&sid)
                .await
                .unwrap()
                .len(),
            2,
            "status advance creates no new history rows"
        );

        // An untrusted target journals nothing, though its payload persists.
        let untrusted_call = Uuid::new_v4();
        session
            .record_inference_request(
                untrusted_call,
                &payload,
                InferenceRequestStatus::Completed,
                &table,
                false,
            )
            .await
            .unwrap();
        assert_eq!(
            db.protected_redaction_history_list(&sid)
                .await
                .unwrap()
                .len(),
            2,
            "untrusted target must not journal"
        );
        assert!(
            db.get_inference_request(&untrusted_call.to_string(), 0)
                .await
                .unwrap()
                .is_some(),
            "untrusted payload row still persists"
        );

        // Atomic rollback reconciled with the decision-12 fallback (F1↔AC9): a
        // fault between the artifact-row write and the journal attach rolls the
        // journal transaction back ATOMICALLY — no history row and no journaled
        // inference row commit together. THEN the decision-12 fallback persists a
        // SCRUBBED inference row via a separate non-journaling insert, so the turn
        // CONTINUES (no error propagated) with: no history rows, a scrubbed
        // inference row present, and the raw literals in no persisted column.
        let db2 = Db::open_in_memory().unwrap();
        let session2 = new_session(db2.clone());
        let call2 = Uuid::new_v4();
        journal_fault::set_fail_after_artifact_row(true);
        let result = session2
            .record_inference_request(
                call2,
                &payload,
                InferenceRequestStatus::Completed,
                &table,
                true,
            )
            .await;
        journal_fault::set_fail_after_artifact_row(false);
        assert!(
            result.is_ok(),
            "a journal-txn fault must fail closed to the scrubbed body, not abort the turn"
        );
        assert!(
            db2.protected_redaction_history_list(&session2.id.to_string())
                .await
                .unwrap()
                .is_empty(),
            "no history row may commit after the rolled-back journal txn"
        );
        // The scrubbed decision-12 fallback row IS persisted.
        let fallback_row = db2
            .get_inference_request(&call2.to_string(), 0)
            .await
            .unwrap()
            .expect("scrubbed fallback inference row persisted");
        let stored = serde_json::to_string(&fallback_row.payload).unwrap();
        assert!(
            !stored.contains(ENV_LIT) && !stored.contains(CRED_LIT),
            "no raw matched literal may appear in the fallback row"
        );
        assert!(
            stored.contains("[redacted]"),
            "the fallback row carries the generic placeholder"
        );
    }

    // -- K1 compaction record --------------------------------------------------

    /// A `session_compacted` record embeds the drafting model's brief/handoff
    /// text; a TRUSTED authoring frame journals its table-matched literals to
    /// protected history (decision 10.3 / K1), a frame-less record journals
    /// nothing (today's semantics), and a journal-transaction fault fails closed
    /// by scrubbing the persisted event body.
    #[tokio::test]
    async fn trusted_compaction_record_journals_brief_literal_and_fails_closed() {
        const LIT: &str = "compaction-brief-secret-abc123456";

        let tmp = tempfile::tempdir().unwrap();
        write_trusted_provider(tmp.path());
        let db = Db::open_in_memory().unwrap();
        let session = Session::create(
            db.clone(),
            tmp.path().to_path_buf(),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        let config =
            crate::daemon::session_worker::SessionConfigHandle::from_disk_for_tests(tmp.path());
        let table = env_only_table(LIT);
        let sid = session.id.to_string();

        let record = |brief: &'static str| SessionCompactionRecord {
            successor_session_id: session.id,
            successor_short_id: "succ",
            seed_tool_count: 0,
            brief_text: brief,
            handoff_text: "full handoff",
            source: "manual",
            trigger_ctx_pct: None,
            tokens_before: 0,
            tokens_after: 0,
            turns_summarized: 0,
            tail_kept: 0,
            tail_trimmed: 0,
            tail_messages: &[],
        };
        let trusted_frame = SessionEventModelFrame {
            provider_id: "openai",
            model_id: "gpt-5",
            config: &config,
            session_table: &table,
        };

        // Trusted authoring frame: the brief literal journals with an Event ref.
        let seq = session
            .record_session_compacted_with_source(
                "Build",
                record("handoff brief cites compaction-brief-secret-abc123456"),
                Some(trusted_frame),
            )
            .await
            .unwrap();
        let rows = db.protected_redaction_history_list(&sid).await.unwrap();
        assert_eq!(
            rows.len(),
            1,
            "compaction brief literal journaled: {rows:#?}"
        );
        let refs = db
            .protected_redaction_artifact_refs_for_artifact(
                RedactionArtifactKind::Event,
                &seq.to_string(),
            )
            .await
            .unwrap();
        assert_eq!(refs.len(), 1, "one Event ref for the compaction seq");
        assert_eq!(refs[0].history_id, rows[0].history_id);

        // A frame-less compaction record journals nothing.
        session
            .record_session_compacted_with_source(
                "Build",
                record("frame-less brief cites compaction-brief-secret-abc123456"),
                None,
            )
            .await
            .unwrap();
        assert_eq!(
            db.protected_redaction_history_list(&sid)
                .await
                .unwrap()
                .len(),
            1,
            "a frame-less compaction record adds no history rows"
        );

        // A journal-transaction fault fails closed: no new history row and the
        // persisted event body carries the placeholder in place of the literal.
        let before = db
            .protected_redaction_history_list(&sid)
            .await
            .unwrap()
            .len();
        journal_fault::set_fail_after_artifact_row(true);
        let seam_seq = session
            .record_session_compacted_with_source(
                "Build",
                record("faulted brief cites compaction-brief-secret-abc123456"),
                Some(trusted_frame),
            )
            .await
            .expect("a journal fault must fail closed, not abort");
        journal_fault::set_fail_after_artifact_row(false);
        assert_eq!(
            db.protected_redaction_history_list(&sid)
                .await
                .unwrap()
                .len(),
            before,
            "the faulted compaction journal commits no history row"
        );
        let events = db.list_session_events(session.id).await.unwrap();
        let event = events
            .iter()
            .find(|e| e.seq == seam_seq)
            .expect("scrubbed compaction event persisted");
        let stored = serde_json::to_string(&event.data).unwrap();
        assert!(!stored.contains(LIT), "matched literal must be scrubbed");
        assert!(stored.contains("[redacted]"), "generic placeholder present");
    }

    // -- AC10 ----------------------------------------------------------------

    #[tokio::test]
    async fn trusted_event_persistence_journals_response_tool_event_artifacts() {
        const LIT: &str = "event-env-secret-literal-abc123456";

        let tmp = tempfile::tempdir().unwrap();
        write_trusted_provider(tmp.path());
        let db = Db::open_in_memory().unwrap();
        let session = Session::create(
            db.clone(),
            tmp.path().to_path_buf(),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        session.set_active_model("openai", "gpt-5").unwrap();
        let config =
            crate::daemon::session_worker::SessionConfigHandle::from_disk_for_tests(tmp.path());
        let table = env_only_table(LIT);

        // Provider response (AssistantMessage) -> Response, tool result
        // (ToolCallCompleted) -> Tool, and another model-authored kind
        // (SubagentReport) -> Event. All carry the same table literal.
        let response_seq = session
            .record_event_with_model_frame(
                SessionEventKind::AssistantMessage,
                Some("Build"),
                None,
                SessionEventModelFrame {
                    provider_id: "openai",
                    model_id: "gpt-5",
                    config: &config,
                    session_table: &table,
                },
                &serde_json::json!({"text": format!("model said {LIT}")}),
            )
            .await
            .unwrap();
        let tool_seq = session
            .record_event_with_model_frame(
                SessionEventKind::ToolCallCompleted,
                Some("Build"),
                Some("call-1"),
                SessionEventModelFrame {
                    provider_id: "openai",
                    model_id: "gpt-5",
                    config: &config,
                    session_table: &table,
                },
                &serde_json::json!({"output": format!("tool result {LIT}")}),
            )
            .await
            .unwrap();
        let event_seq = session
            .record_event_with_model_frame(
                SessionEventKind::SubagentReport,
                Some("Build"),
                None,
                SessionEventModelFrame {
                    provider_id: "openai",
                    model_id: "gpt-5",
                    config: &config,
                    session_table: &table,
                },
                &serde_json::json!({"report": format!("subagent said {LIT}")}),
            )
            .await
            .unwrap();

        // The same literal dedups to one history row referenced by all three
        // events, each ref carrying the committed event `seq` as its artifact id.
        let sid = session.id.to_string();
        let rows = db.protected_redaction_history_list(&sid).await.unwrap();
        assert_eq!(rows.len(), 1, "same literal dedups to one history row");
        assert_eq!(rows[0].ref_count, 3, "one ref per journaled event");
        let history_id = rows[0].history_id.clone();

        for (kind, seq) in [
            (RedactionArtifactKind::Response, response_seq),
            (RedactionArtifactKind::Tool, tool_seq),
            (RedactionArtifactKind::Event, event_seq),
        ] {
            let refs = db
                .protected_redaction_artifact_refs_for_artifact(kind, &seq.to_string())
                .await
                .unwrap();
            assert_eq!(refs.len(), 1, "expected one {kind:?} ref for seq {seq}");
            assert_eq!(refs[0].history_id, history_id);
        }

        // A non-model-authored Notice with the same literal journals nothing.
        let notice_seq = session
            .record_notice(Some("Build"), &format!("notice mentions {LIT}"), "engine")
            .await
            .unwrap();
        assert_eq!(
            db.protected_redaction_history_list(&sid)
                .await
                .unwrap()
                .len(),
            1,
            "a non-model-authored Notice must not journal"
        );
        for kind in [
            RedactionArtifactKind::Event,
            RedactionArtifactKind::Response,
            RedactionArtifactKind::Tool,
        ] {
            assert!(
                db.protected_redaction_artifact_refs_for_artifact(kind, &notice_seq.to_string())
                    .await
                    .unwrap()
                    .is_empty(),
                "notice seq {notice_seq} must have no journal ref"
            );
        }

        // Event fault seam (AC10 + F1): arming the mid-transaction seam rolls the
        // event journal txn back ATOMICALLY (the event row and its history/refs
        // both absent), THEN the decision-12 fallback persists a SCRUBBED event
        // body via a separate non-journaling insert — the turn CONTINUES and no
        // new history row commits.
        let history_before = db
            .protected_redaction_history_list(&sid)
            .await
            .unwrap()
            .len();
        journal_fault::set_fail_after_artifact_row(true);
        let seam_seq = session
            .record_event_with_model_frame(
                SessionEventKind::AssistantMessage,
                Some("Build"),
                None,
                SessionEventModelFrame {
                    provider_id: "openai",
                    model_id: "gpt-5",
                    config: &config,
                    session_table: &table,
                },
                &serde_json::json!({"text": format!("second turn said {LIT}")}),
            )
            .await
            .expect("event journal-txn fault must fail closed, not abort the turn");
        journal_fault::set_fail_after_artifact_row(false);
        assert_eq!(
            db.protected_redaction_history_list(&sid)
                .await
                .unwrap()
                .len(),
            history_before,
            "the rolled-back event journal txn commits no new history row"
        );
        let events = db.list_session_events(session.id).await.unwrap();
        let seam_event = events
            .iter()
            .find(|e| e.seq == seam_seq)
            .expect("scrubbed fallback event persisted");
        let seam_body = serde_json::to_string(&seam_event.data).unwrap();
        assert!(
            !seam_body.contains(LIT),
            "the fallback event body scrubs the raw literal"
        );
        assert!(
            seam_body.contains("[redacted]"),
            "the fallback event body carries the generic placeholder"
        );
    }

    // -- AC11 ----------------------------------------------------------------

    /// Boot the production secure-key actor over a caller-held [`FakeNativeStore`]
    /// (AC15: `MapKeyResolver` is for pure-crypto unit tests only, never the
    /// journaling resolver). Mirrors the protected-history AC7 pattern:
    /// `start_with_store` blocks on the actor readiness handshake, so it is booted
    /// on a plain thread, never a Tokio worker.
    async fn boot_fake_secure_key_actor(
        db: &Db,
        store: &crate::secure_key::fake::FakeNativeStore,
    ) -> crate::secure_key::SecureKeyActor {
        let db = db.clone();
        let store = store.clone();
        let (tx, rx) = tokio::sync::oneshot::channel();
        std::thread::Builder::new()
            .name("recording-test-secure-key-boot".into())
            .spawn(move || {
                let _ = tx.send(crate::secure_key::SecureKeyActor::start_with_store(
                    db,
                    Box::new(store),
                    std::sync::Arc::new(crate::secure_key::FailClosedReconciler),
                ));
            })
            .expect("spawn secure key boot thread");
        rx.await
            .expect("secure key boot channel")
            .expect("secure key actor")
    }

    /// Shut the actor down off the runtime (`Drop` blocks on the worker reply).
    async fn shutdown_fake_secure_key_actor(actor: crate::secure_key::SecureKeyActor) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        std::thread::Builder::new()
            .name("recording-test-secure-key-shutdown".into())
            .spawn(move || {
                drop(actor);
                let _ = tx.send(());
            })
            .expect("spawn secure key shutdown thread");
        rx.await.expect("secure key shutdown channel");
    }

    #[tokio::test]
    async fn trusted_persistence_fails_closed_to_redacted_artifact_on_journal_failure() {
        use crate::secure_key::fake::{FakeNativeStore, FaultKind, FaultPoint, InjectedFault};

        let db = Db::open_in_memory().unwrap();
        // AC15: drive the PRODUCTION store-backed resolver, not `MapKeyResolver`.
        // The FakeNativeStore is faulted (every key get/set fails closed) so the
        // resolver's `ensure_active` — and therefore `prepare_append` — fails the
        // moment journaling tries to load key material, exercising the real
        // decision-12 fallback rather than a synthetic empty-map resolver.
        let store = FakeNativeStore::new();
        let actor = boot_fake_secure_key_actor(&db, &store).await;
        store.inject(
            FaultPoint::BeforeGet,
            InjectedFault::Error(FaultKind::Unavailable),
        );
        store.inject(
            FaultPoint::BeforeSet,
            InjectedFault::Error(FaultKind::Unavailable),
        );
        let resolver: std::sync::Arc<
            dyn crate::redact::protected_redaction_history::RedactionKeyResolver,
        > = std::sync::Arc::new(crate::redact::secure_key_resolver::SecureKeyResolver::new(
            actor.handle(),
        ));
        let session =
            Session::create(db.clone(), PathBuf::from("/proj"), "Build", resolver).unwrap();
        let table = env_credential_table();
        let call_id = Uuid::new_v4();
        let payload = serde_json::json!({
            "messages": [{"role": "user", "content": format!("deploy {ENV_LIT} using {CRED_LIT}")}],
        });

        // The turn is not aborted: the redacted body persists.
        session
            .record_inference_request(
                call_id,
                &payload,
                InferenceRequestStatus::Completed,
                &table,
                true,
            )
            .await
            .unwrap();

        let sid = session.id.to_string();
        assert!(
            db.protected_redaction_history_list(&sid)
                .await
                .unwrap()
                .is_empty(),
            "journal failure leaves no history row"
        );

        // The persisted payload replaces each matched literal with the generic
        // placeholder and carries neither raw literal.
        let row = db
            .get_inference_request(&call_id.to_string(), 0)
            .await
            .unwrap()
            .expect("redacted payload persisted");
        let stored = serde_json::to_string(&row.payload).unwrap();
        assert!(
            !stored.contains(ENV_LIT),
            "matched env literal must be scrubbed"
        );
        assert!(
            !stored.contains(CRED_LIT),
            "matched credential literal must be scrubbed"
        );
        assert!(stored.contains("[redacted]"), "generic placeholder present");

        // Scan the raw persisted column bytes for this artifact: no matched
        // literal appears anywhere in the stored row.
        let cid = call_id.to_string();
        let raw: String = db
            .read(move |conn| {
                let v: String = conn.query_row(
                    "SELECT payload_json FROM inference_requests WHERE call_id = ?1 AND ordinal = 0",
                    [cid],
                    |r| r.get(0),
                )?;
                Ok(v)
            })
            .await
            .unwrap();
        assert!(
            !raw.contains(ENV_LIT),
            "raw column must not carry the env literal"
        );
        assert!(
            !raw.contains(CRED_LIT),
            "raw column must not carry the credential literal"
        );

        shutdown_fake_secure_key_actor(actor).await;
    }

    /// AC15 disabled `RedactConfig` (the `redact.enabled = false` opt-out) that
    /// still collects entries — the flag is a scrub-time opt-out, never a reason
    /// to skip collection, so the fail-closed path can still enforce it.
    fn disabled_redact_cfg() -> crate::config::extended::RedactConfig {
        crate::config::extended::RedactConfig {
            enabled: false,
            ..redact_cfg()
        }
    }

    /// Boot a session whose journaling resolver is backed by a FaultKind::
    /// Unavailable [`FakeNativeStore`] (AC15) — every key get/set fails closed, so
    /// the first `prepare_append` a trusted persistence attempts fails and drives
    /// the real decision-12 fallback (never a synthetic empty-map resolver). The
    /// returned actor must be shut down with [`shutdown_fake_secure_key_actor`].
    async fn faulted_journaling_session(db: &Db) -> (Session, crate::secure_key::SecureKeyActor) {
        use crate::secure_key::fake::{FakeNativeStore, FaultKind, FaultPoint, InjectedFault};
        let store = FakeNativeStore::new();
        let actor = boot_fake_secure_key_actor(db, &store).await;
        store.inject(
            FaultPoint::BeforeGet,
            InjectedFault::Error(FaultKind::Unavailable),
        );
        store.inject(
            FaultPoint::BeforeSet,
            InjectedFault::Error(FaultKind::Unavailable),
        );
        let resolver: std::sync::Arc<
            dyn crate::redact::protected_redaction_history::RedactionKeyResolver,
        > = std::sync::Arc::new(crate::redact::secure_key_resolver::SecureKeyResolver::new(
            actor.handle(),
        ));
        let session =
            Session::create(db.clone(), PathBuf::from("/proj"), "Build", resolver).unwrap();
        (session, actor)
    }

    /// Read back the raw `payload_json` column bytes for a persisted inference
    /// attempt so a test can assert directly on the stored form.
    async fn stored_payload_json(db: &Db, call_id: Uuid) -> String {
        let cid = call_id.to_string();
        db.read(move |conn| {
            let v: String = conn.query_row(
                "SELECT payload_json FROM inference_requests WHERE call_id = ?1 AND ordinal = 0",
                [cid],
                |r| r.get(0),
            )?;
            Ok(v)
        })
        .await
        .unwrap()
    }

    // -- AC15 production fail-closed coverage (H6) ---------------------------
    //
    // Each drives the PRODUCTION `record_inference_request` chokepoint against a
    // trusted target with the fault-injected store-backed resolver, so the real
    // decision-12 fallback (`scrub_body_fail_closed`) is exercised — not a
    // synthetic scrub. They assert that the persisted column carries NO raw
    // literal (and, for the overlap case, no stray suffix) and DOES carry the
    // generic placeholder.

    /// (a) Overlapping table literals `secret` + `secretX`: the pre-G4a
    /// sequential `str::replace` scrubbed `secret` first and left the longer
    /// match's `X` suffix raw. The leftmost-longest production scrub must consume
    /// `secretX` whole, leaving no stray `X`. (The old weak fail-closed test used
    /// only non-overlapping literals and would have passed with the G4a bug live.)
    #[tokio::test]
    async fn fail_closed_scrubs_overlapping_literals_on_journal_failure() {
        let db = Db::open_in_memory().unwrap();
        let (session, actor) = faulted_journaling_session(&db).await;
        // Both literals as forced stored secrets so both are retained as distinct
        // table entries regardless of length/prune heuristics.
        let table = RedactionTable::build_with_env_and_secrets(
            &redact_cfg(),
            Path::new("."),
            &std::collections::HashMap::new(),
            [
                ("ovl_short".to_string(), "secret".to_string()),
                ("ovl_long".to_string(), "secretX".to_string()),
            ],
        )
        .unwrap();
        let call_id = Uuid::new_v4();
        // `secretX` (must scrub whole) then a standalone `secret`.
        let payload = serde_json::json!({
            "messages": [{"role": "user", "content": "token secretX then secret alone"}],
        });
        session
            .record_inference_request(
                call_id,
                &payload,
                InferenceRequestStatus::Completed,
                &table,
                true,
            )
            .await
            .unwrap();

        assert!(
            db.protected_redaction_history_list(&session.id.to_string())
                .await
                .unwrap()
                .is_empty(),
            "journal failure leaves no history row"
        );
        let raw = stored_payload_json(&db, call_id).await;
        assert!(
            !raw.contains("secretX"),
            "the longer overlapping literal is scrubbed whole"
        );
        assert!(
            !raw.contains("secret"),
            "no raw literal (short or long) survives in the persisted column"
        );
        assert!(
            !raw.contains("[redacted]X"),
            "no stray `X` suffix — the G4a sequential-scrub bug is not present"
        );
        assert!(raw.contains("[redacted]"), "generic placeholder present");
        shutdown_fake_secure_key_actor(actor).await;
    }

    /// (b) A numeric table literal appearing as a JSON NUMBER scalar (a PIN in
    /// `{"pin": 7654321}`) — a string-only walk misses it (G4b). The scalar leaf
    /// must be matched by its canonical text and replaced, so the bare number
    /// never survives in the persisted column.
    #[tokio::test]
    async fn fail_closed_scrubs_numeric_scalar_on_journal_failure() {
        let db = Db::open_in_memory().unwrap();
        let (session, actor) = faulted_journaling_session(&db).await;
        // Forced stored secret so the all-digits literal is retained verbatim.
        let table = RedactionTable::build_with_env_and_secrets(
            &redact_cfg(),
            Path::new("."),
            &std::collections::HashMap::new(),
            [("pin_secret".to_string(), "7654321".to_string())],
        )
        .unwrap();
        let call_id = Uuid::new_v4();
        // The literal rides as a JSON number, not a string.
        let payload = serde_json::json!({
            "messages": [{"role": "user", "pin": 7654321}],
        });
        session
            .record_inference_request(
                call_id,
                &payload,
                InferenceRequestStatus::Completed,
                &table,
                true,
            )
            .await
            .unwrap();

        assert!(
            db.protected_redaction_history_list(&session.id.to_string())
                .await
                .unwrap()
                .is_empty(),
            "journal failure leaves no history row"
        );
        let raw = stored_payload_json(&db, call_id).await;
        assert!(
            !raw.contains("7654321"),
            "the numeric scalar literal is scrubbed even as a bare JSON number (G4b)"
        );
        assert!(raw.contains("[redacted]"), "generic placeholder present");
        shutdown_fake_secure_key_actor(actor).await;
    }

    /// (c) The `redact.enabled = false` disabled-table fallback: decision 12 is
    /// fail-closed regardless of the live opt-out, so `scrub_body_fail_closed`
    /// forces enforcement of a disabled table. A disabled table still collects
    /// entries and its matcher still matches (both `match_literals_in_json` and
    /// the scrub ignore the flag), so the raw literal must not survive.
    #[tokio::test]
    async fn fail_closed_enforces_disabled_table_on_journal_failure() {
        let db = Db::open_in_memory().unwrap();
        let (session, actor) = faulted_journaling_session(&db).await;
        const DIS_LIT: &str = "disabled-optout-secret-55221";
        let table = RedactionTable::build_with_env_and_secrets(
            &disabled_redact_cfg(),
            Path::new("."),
            &std::collections::HashMap::new(),
            [("stored_api".to_string(), DIS_LIT.to_string())],
        )
        .unwrap();
        assert!(
            table.disabled(),
            "table reflects the redact.enabled=false opt-out"
        );
        let call_id = Uuid::new_v4();
        let payload = serde_json::json!({
            "messages": [{"role": "user", "content": format!("call with {DIS_LIT}")}],
        });
        session
            .record_inference_request(
                call_id,
                &payload,
                InferenceRequestStatus::Completed,
                &table,
                true,
            )
            .await
            .unwrap();

        assert!(
            db.protected_redaction_history_list(&session.id.to_string())
                .await
                .unwrap()
                .is_empty(),
            "journal failure leaves no history row"
        );
        let raw = stored_payload_json(&db, call_id).await;
        assert!(
            !raw.contains(DIS_LIT),
            "the disabled opt-out is overridden fail-closed: no raw literal in the persisted column"
        );
        assert!(raw.contains("[redacted]"), "generic placeholder present");
        shutdown_fake_secure_key_actor(actor).await;
    }

    // -- AC11 tandem (model-comparison shadow) production path (J6) -----------
    //
    // Drive the PRODUCTION `record_tandem_inference` chokepoint so a revert of
    // the trusted-tandem journaling would fail here.

    /// Read the raw `request_json`/`response_json` columns for a persisted tandem
    /// row so a test can assert directly on the stored bytes.
    async fn stored_tandem_columns(db: &Db, id: &str) -> (String, String) {
        let id = id.to_owned();
        db.read(move |conn| {
            let row: (String, Option<String>) = conn.query_row(
                "SELECT request_json, response_json FROM tandem_inference WHERE id = ?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            Ok((row.0, row.1.unwrap_or_default()))
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn trusted_tandem_journals_request_and_response_refs_and_is_idempotent() {
        let db = Db::open_in_memory().unwrap();
        let session = new_session(db.clone());
        let table = env_credential_table();
        let sid = session.id.to_string();
        let tandem_id = Uuid::new_v4().to_string();
        let parent_call = Uuid::new_v4().to_string();
        // env literal rides in the REQUEST, credential literal in the RESPONSE:
        // each side is a distinct artifact and must journal under its own kind.
        let request = serde_json::json!({
            "messages": [{"role": "user", "content": format!("deploy {ENV_LIT}")}],
        });
        let response = serde_json::json!({
            "content": format!("model echoed {CRED_LIT}"),
        });

        // (a) Trusted target, pending dispatch write: both sides journal.
        session
            .record_tandem_inference(
                &tandem_id,
                &parent_call,
                None,
                Some("Build"),
                "selfhosted",
                "local-trusted",
                &request,
                Some(&response),
                None,
                InferenceRequestStatus::Pending,
                &table,
                true,
            )
            .await
            .unwrap();

        let rows = db.protected_redaction_history_list(&sid).await.unwrap();
        assert_eq!(rows.len(), 2, "env + credential both journaled: {rows:#?}");
        let env_row = rows
            .iter()
            .find(|r| r.source == RedactionHistorySource::Environment)
            .expect("env history row");
        let cred_row = rows
            .iter()
            .find(|r| r.source == RedactionHistorySource::Credential)
            .expect("credential history row");

        // Request ref (keyed by the tandem row id) → the env literal;
        // Response ref (same key) → the credential literal.
        let req_refs = db
            .protected_redaction_artifact_refs_for_artifact(
                RedactionArtifactKind::Request,
                &tandem_id,
            )
            .await
            .unwrap();
        assert_eq!(req_refs.len(), 1, "one Request ref keyed by the tandem row");
        assert_eq!(req_refs[0].history_id, env_row.history_id);
        let resp_refs = db
            .protected_redaction_artifact_refs_for_artifact(
                RedactionArtifactKind::Response,
                &tandem_id,
            )
            .await
            .unwrap();
        assert_eq!(
            resp_refs.len(),
            1,
            "one Response ref keyed by the tandem row"
        );
        assert_eq!(resp_refs[0].history_id, cred_row.history_id);

        // (b) pending→settle: the settle upsert re-journals the SAME bodies but
        // `append_and_attach_conn` dedups the history row and idempotently
        // re-attaches the ref — no extra history rows, no extra refs.
        session
            .record_tandem_inference(
                &tandem_id,
                &parent_call,
                None,
                Some("Build"),
                "selfhosted",
                "local-trusted",
                &request,
                Some(&response),
                Some(&serde_json::json!({"input_tokens": 10})),
                InferenceRequestStatus::Completed,
                &table,
                true,
            )
            .await
            .unwrap();
        assert_eq!(
            db.protected_redaction_history_list(&sid)
                .await
                .unwrap()
                .len(),
            2,
            "settle re-journal must dedup: no new history rows"
        );
        assert_eq!(
            db.protected_redaction_artifact_refs_for_artifact(
                RedactionArtifactKind::Request,
                &tandem_id,
            )
            .await
            .unwrap()
            .len(),
            1,
            "settle re-attach is idempotent for the Request ref"
        );
        assert_eq!(
            db.protected_redaction_artifact_refs_for_artifact(
                RedactionArtifactKind::Response,
                &tandem_id,
            )
            .await
            .unwrap()
            .len(),
            1,
            "settle re-attach is idempotent for the Response ref"
        );

        // (c) An UNTRUSTED tandem target journals nothing (its bodies are already
        // post-redaction), though the row still persists.
        let untrusted_id = Uuid::new_v4().to_string();
        session
            .record_tandem_inference(
                &untrusted_id,
                &parent_call,
                None,
                Some("Build"),
                "cloud",
                "cloud-untrusted",
                &request,
                Some(&response),
                None,
                InferenceRequestStatus::Completed,
                &table,
                false,
            )
            .await
            .unwrap();
        assert_eq!(
            db.protected_redaction_history_list(&sid)
                .await
                .unwrap()
                .len(),
            2,
            "untrusted tandem target must not journal"
        );
        assert!(
            db.protected_redaction_artifact_refs_for_artifact(
                RedactionArtifactKind::Request,
                &untrusted_id,
            )
            .await
            .unwrap()
            .is_empty(),
            "untrusted tandem row carries no journal ref"
        );
    }

    #[tokio::test]
    async fn faulted_trusted_tandem_fails_closed_scrubbing_both_bodies() {
        // (d) A faulted store-backed resolver (AC15): the first `prepare_append`
        // fails, so trusted tandem journaling falls closed — BOTH request and
        // response bodies are scrubbed, no history row is written, and neither raw
        // literal survives in the persisted columns. The write is not aborted.
        let db = Db::open_in_memory().unwrap();
        let (session, actor) = faulted_journaling_session(&db).await;
        let table = env_credential_table();
        let tandem_id = Uuid::new_v4().to_string();
        let request = serde_json::json!({
            "messages": [{"role": "user", "content": format!("deploy {ENV_LIT}")}],
        });
        let response = serde_json::json!({
            "content": format!("model echoed {CRED_LIT}"),
        });

        session
            .record_tandem_inference(
                &tandem_id,
                "parent-1",
                None,
                Some("Build"),
                "selfhosted",
                "local-trusted",
                &request,
                Some(&response),
                None,
                InferenceRequestStatus::Completed,
                &table,
                true,
            )
            .await
            .unwrap();

        assert!(
            db.protected_redaction_history_list(&session.id.to_string())
                .await
                .unwrap()
                .is_empty(),
            "tandem journal failure leaves no history row"
        );
        let (req_raw, resp_raw) = stored_tandem_columns(&db, &tandem_id).await;
        assert!(
            !req_raw.contains(ENV_LIT) && !req_raw.contains(CRED_LIT),
            "request column carries no raw literal after fail-closed scrub"
        );
        assert!(
            !resp_raw.contains(ENV_LIT) && !resp_raw.contains(CRED_LIT),
            "response column carries no raw literal after fail-closed scrub"
        );
        assert!(
            req_raw.contains("[redacted]"),
            "request scrub placeholder present"
        );
        assert!(
            resp_raw.contains("[redacted]"),
            "response scrub placeholder present"
        );
        shutdown_fake_secure_key_actor(actor).await;
    }

    // -- AC10 subagent-report / spawned / docs-report event routes (J6) ------
    //
    // The driver's noninteractive finalizers author SubagentReport (incl. the
    // `docs` pipeline report) and the batch SubagentSpawned through
    // `record_event_with_model_frame` with the CHILD/docs model's frame. These
    // drive the same chokepoint through the SAME frame shape the production
    // caller builds (provider/model id + `config` + pre-policy `session_table`),
    // so a revert of any caller to frame-less `record_event` — or a broken frame
    // — would leave a trusted model-authored event's table literal unjournaled
    // and would fail these assertions. The companion source guard in the driver
    // test module proves the docs finalizers actually supply that frame.

    /// Providers config carrying a trusted (`gpt-5`) and an untrusted
    /// (`cloud-mini`) model, so a frame can resolve either trust class.
    fn write_trusted_and_untrusted_providers(root: &Path) {
        let cockpit = root.join(".cockpit");
        let providers = cockpit.join("providers");
        std::fs::create_dir_all(&providers).unwrap();
        std::fs::write(cockpit.join("config.json"), r#"{"llm_mode":"defensive"}"#).unwrap();
        std::fs::write(
            providers.join("openai.json"),
            serde_json::json!({
                "url": "https://example.test/v1",
                "models": [{"id": "gpt-5", "trust": "trusted", "mode": "frontier"}],
            })
            .to_string(),
        )
        .unwrap();
        std::fs::write(
            providers.join("cloud.json"),
            serde_json::json!({
                "url": "https://cloud.test/v1",
                "models": [{"id": "cloud-mini", "trust": "untrusted", "mode": "frontier"}],
            })
            .to_string(),
        )
        .unwrap();
    }

    #[tokio::test]
    async fn trusted_subagent_report_spawn_and_docs_events_journal_untrusted_no_op() {
        const LIT: &str = "subagent-route-secret-abc123456";

        let tmp = tempfile::tempdir().unwrap();
        write_trusted_and_untrusted_providers(tmp.path());
        let db = Db::open_in_memory().unwrap();
        let session = Session::create(
            db.clone(),
            tmp.path().to_path_buf(),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        let config =
            crate::daemon::session_worker::SessionConfigHandle::from_disk_for_tests(tmp.path());
        let table = env_only_table(LIT);
        let sid = session.id.to_string();

        // `SessionEventModelFrame` is `Copy`, so one binding serves every write.
        let trusted_frame = SessionEventModelFrame {
            provider_id: "openai",
            model_id: "gpt-5",
            config: &config,
            session_table: &table,
        };

        // A trusted subagent report (the interactive/noninteractive finalizer
        // route), a trusted batch SubagentSpawned (model-authored `prompt`/`why`
        // free text), and a trusted `docs` pipeline report — all with the SAME
        // table literal — each journal against the child/docs model's trust and
        // dedup to a single history row.
        let report_seq = session
            .record_event_with_model_frame(
                SessionEventKind::SubagentReport,
                Some("explore"),
                Some("task-1"),
                trusted_frame,
                &serde_json::json!({"report": format!("child said {LIT}")}),
            )
            .await
            .unwrap();
        let spawn_seq = session
            .record_event_with_model_frame(
                SessionEventKind::SubagentSpawned,
                Some("Build"),
                Some("task-2"),
                trusted_frame,
                &serde_json::json!({"prompt": format!("spawn brief mentions {LIT}"), "why": "x"}),
            )
            .await
            .unwrap();
        let docs_seq = session
            .record_event_with_model_frame(
                SessionEventKind::SubagentReport,
                Some("docs"),
                Some("task-3"),
                trusted_frame,
                &serde_json::json!({"report": format!("docs answer cites {LIT}")}),
            )
            .await
            .unwrap();

        let rows = db.protected_redaction_history_list(&sid).await.unwrap();
        assert_eq!(rows.len(), 1, "same literal dedups to one history row");
        assert_eq!(
            rows[0].ref_count, 3,
            "one Event ref per journaled model-authored event"
        );
        let history_id = rows[0].history_id.clone();
        for seq in [report_seq, spawn_seq, docs_seq] {
            let refs = db
                .protected_redaction_artifact_refs_for_artifact(
                    RedactionArtifactKind::Event,
                    &seq.to_string(),
                )
                .await
                .unwrap();
            assert_eq!(refs.len(), 1, "expected one Event ref for seq {seq}");
            assert_eq!(refs[0].history_id, history_id);
        }

        // The SAME events authored by an UNTRUSTED model journal nothing — their
        // bodies are already post-redaction.
        let untrusted_frame = SessionEventModelFrame {
            provider_id: "cloud",
            model_id: "cloud-mini",
            config: &config,
            session_table: &table,
        };
        for (kind, agent) in [
            (SessionEventKind::SubagentReport, "explore"),
            (SessionEventKind::SubagentSpawned, "Build"),
            (SessionEventKind::SubagentReport, "docs"),
        ] {
            let seq = session
                .record_event_with_model_frame(
                    kind,
                    Some(agent),
                    None,
                    untrusted_frame,
                    &serde_json::json!({"report": format!("untrusted mentions {LIT}"), "prompt": format!("brief {LIT}")}),
                )
                .await
                .unwrap();
            assert!(
                db.protected_redaction_artifact_refs_for_artifact(
                    RedactionArtifactKind::Event,
                    &seq.to_string(),
                )
                .await
                .unwrap()
                .is_empty(),
                "untrusted {kind:?} must not journal"
            );
        }
        assert_eq!(
            db.protected_redaction_history_list(&sid)
                .await
                .unwrap()
                .len(),
            1,
            "untrusted model-authored events add no history rows"
        );
    }

    #[tokio::test]
    async fn faulted_trusted_subagent_report_fails_closed_scrubbing_event_body() {
        const LIT: &str = "docs-report-secret-xyz987654";

        let tmp = tempfile::tempdir().unwrap();
        write_trusted_and_untrusted_providers(tmp.path());
        let db = Db::open_in_memory().unwrap();
        // Faulted store-backed resolver (AC15): the trust class is resolved from
        // the frame's config (trusted), so journaling is attempted and its first
        // `prepare_append` fails — driving the real decision-12 event fallback.
        let (session, actor) = faulted_journaling_session(&db).await;
        let config =
            crate::daemon::session_worker::SessionConfigHandle::from_disk_for_tests(tmp.path());
        let table = env_only_table(LIT);

        let seq = session
            .record_event_with_model_frame(
                SessionEventKind::SubagentReport,
                Some("docs"),
                Some("task-9"),
                SessionEventModelFrame {
                    provider_id: "openai",
                    model_id: "gpt-5",
                    config: &config,
                    session_table: &table,
                },
                &serde_json::json!({"report": format!("docs answer cites {LIT}")}),
            )
            .await
            .expect("event journal failure must fail closed, not abort the turn");

        assert!(
            db.protected_redaction_history_list(&session.id.to_string())
                .await
                .unwrap()
                .is_empty(),
            "journal failure leaves no history row"
        );
        let events = db.list_session_events(session.id).await.unwrap();
        let event = events
            .iter()
            .find(|e| e.seq == seq)
            .expect("scrubbed fallback event persisted");
        let body = serde_json::to_string(&event.data).unwrap();
        assert!(
            !body.contains(LIT),
            "fallback event body scrubs the raw literal"
        );
        assert!(
            body.contains("[redacted]"),
            "fallback event carries the placeholder"
        );
        shutdown_fake_secure_key_actor(actor).await;
    }

    // -- tool_call_events audit-row fail-closed (finding r11-3, decision 12) ---
    //
    // All three live tool-call dispatch paths (ordinary tool call, `schedule`
    // meta-tool, MCP child) co-persist their raw model-supplied args into
    // `tool_call_events` and funnel that write through
    // `record_tool_call_journaled`. These drive that shared chokepoint directly
    // — the security-critical journal/scrub logic the three paths share.

    /// Build a `ToolCallRow` carrying an ENVIRONMENT literal in its args
    /// (`original`/`wire`) and a CREDENTIAL literal in its `output`, so the
    /// journal/scrub covers both secret-bearing fields and both source classes.
    fn audit_row_with_literals(tool: &str, call_id: &str) -> ToolCallRow {
        ToolCallRow {
            event_id: Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
            agent: "Build".to_string(),
            call_id: call_id.to_string(),
            parent_call_id: None,
            parent_child_index: None,
            identity: crate::session::ToolCallProviderIdentity::default(),
            tool: tool.to_string(),
            mcp_server: None,
            path: None,
            original_input_json: serde_json::json!({ "command": format!("deploy {ENV_LIT}") }),
            wire_input_json: serde_json::json!({ "command": format!("deploy {ENV_LIT}") }),
            recovery: crate::db::tool_calls::Recovery::Clean,
            hard_fail: false,
            exit_code: None,
            sandbox_enabled: false,
            sandboxed: false,
            sandbox_unavailable_reason: None,
            output: format!("tool echoed {CRED_LIT}"),
            truncated: false,
            duration_ms: 5,
            llm_mode: crate::config::extended::LlmMode::default(),
            shape_fingerprint: None,
            hint: None,
        }
    }

    /// Read back the raw `tool_call_events` column bytes for one audit row so a
    /// test can assert directly on the stored (original/wire/output) forms.
    async fn stored_tool_call_columns(db: &Db, event_id: Uuid) -> (String, String, String) {
        let eid = event_id.to_string();
        db.read(move |conn| {
            let row = conn.query_row(
                "SELECT original_input_json, wire_input_json, output \
                 FROM tool_call_events WHERE event_id = ?1",
                [eid],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                    ))
                },
            )?;
            Ok(row)
        })
        .await
        .unwrap()
    }

    /// AC1: a TRUSTED author with a matched literal in its args (and output),
    /// under a FAULTED store-backed resolver (AC15), leaves NO raw matched
    /// literal in `tool_call_events` (scrubbed) and NO orphan artifact ref — for
    /// a row shaped like EACH of the three tool-call paths.
    #[tokio::test]
    async fn trusted_tool_call_audit_row_fails_closed_for_all_three_paths() {
        for (tool, call_id) in [
            ("bash", "call-ordinary"),
            ("schedule", "call-schedule"),
            ("mcp_child", "call-mcp"),
        ] {
            let db = Db::open_in_memory().unwrap();
            let (session, actor) = faulted_journaling_session(&db).await;
            let table = env_credential_table();
            let row = audit_row_with_literals(tool, call_id);
            let event_id = row.event_id;

            // The turn is not aborted: the redacted row persists.
            session
                .record_tool_call_journaled(row, &table, true)
                .await
                .unwrap();

            let sid = session.id.to_string();
            assert!(
                db.protected_redaction_history_list(&sid)
                    .await
                    .unwrap()
                    .is_empty(),
                "{tool}: a faulted journal leaves no history row"
            );
            assert!(
                db.protected_redaction_artifact_refs_for_artifact(
                    RedactionArtifactKind::Tool,
                    &event_id.to_string(),
                )
                .await
                .unwrap()
                .is_empty(),
                "{tool}: no orphan Tool ref points at the scrubbed audit row"
            );

            let (orig, wire, output) = stored_tool_call_columns(&db, event_id).await;
            for (label, col) in [("original", &orig), ("wire", &wire), ("output", &output)] {
                assert!(
                    !col.contains(ENV_LIT),
                    "{tool}: {label} column must not carry the env literal"
                );
                assert!(
                    !col.contains(CRED_LIT),
                    "{tool}: {label} column must not carry the credential literal"
                );
                assert!(
                    col.contains("[redacted]"),
                    "{tool}: {label} column carries the generic placeholder"
                );
            }
            shutdown_fake_secure_key_actor(actor).await;
        }
    }

    /// AC2: on the SUCCESS path the raw args/output are retained locally and the
    /// audit row carries its OWN protected-history ref (kind `Tool`, keyed by
    /// `event_id`) per journaled literal — export redacts via that shared row.
    #[tokio::test]
    async fn trusted_tool_call_audit_row_journals_and_retains_raw_on_success() {
        let db = Db::open_in_memory().unwrap();
        let session = new_session(db.clone());
        let table = env_credential_table();
        let row = audit_row_with_literals("bash", "call-ok");
        let event_id = row.event_id;

        session
            .record_tool_call_journaled(row, &table, true)
            .await
            .unwrap();

        let sid = session.id.to_string();
        assert_eq!(
            db.protected_redaction_history_list(&sid)
                .await
                .unwrap()
                .len(),
            2,
            "the distinct env-arg and cred-output literals journal one row each"
        );
        let refs = db
            .protected_redaction_artifact_refs_for_artifact(
                RedactionArtifactKind::Tool,
                &event_id.to_string(),
            )
            .await
            .unwrap();
        assert_eq!(
            refs.len(),
            2,
            "the audit row carries one Tool ref per journaled literal"
        );

        // Owner retention: the stored row keeps the raw literals (export redacts
        // them via the shared history rows above).
        let (orig, wire, output) = stored_tool_call_columns(&db, event_id).await;
        assert!(
            orig.contains(ENV_LIT) && wire.contains(ENV_LIT),
            "success retains the raw args locally"
        );
        assert!(
            output.contains(CRED_LIT),
            "success retains the raw output locally"
        );
    }

    /// AC3: an UNTRUSTED author is unaffected — even under a faulted resolver the
    /// plain insert is taken (no journaling, no scrub); the args are already
    /// post-redaction upstream and this path never rewrites them.
    #[tokio::test]
    async fn untrusted_tool_call_audit_row_is_unaffected() {
        let db = Db::open_in_memory().unwrap();
        let (session, actor) = faulted_journaling_session(&db).await;
        let table = env_credential_table();
        let row = audit_row_with_literals("bash", "call-untrusted");
        let event_id = row.event_id;

        session
            .record_tool_call_journaled(row, &table, false)
            .await
            .unwrap();

        let sid = session.id.to_string();
        assert!(
            db.protected_redaction_history_list(&sid)
                .await
                .unwrap()
                .is_empty(),
            "an untrusted author journals nothing"
        );
        let (orig, _wire, output) = stored_tool_call_columns(&db, event_id).await;
        assert!(
            orig.contains(ENV_LIT),
            "the untrusted path leaves the args unchanged (no scrub)"
        );
        assert!(
            output.contains(CRED_LIT),
            "the untrusted path leaves the output unchanged (no scrub)"
        );
        shutdown_fake_secure_key_actor(actor).await;
    }

    /// AC9 parity / no-orphan: a mid-transaction fault (after the audit-row write,
    /// before the journal attach) rolls the whole transaction back ATOMICALLY —
    /// no history row, no orphan ref — THEN the decision-12 fallback persists a
    /// SCRUBBED row via a separate non-journaling insert; the turn continues.
    #[tokio::test]
    async fn trusted_tool_call_audit_row_seam_fault_rolls_back_and_scrubs() {
        let db = Db::open_in_memory().unwrap();
        let session = new_session(db.clone());
        let table = env_credential_table();
        let row = audit_row_with_literals("bash", "call-seam");
        let event_id = row.event_id;

        journal_fault::set_fail_after_artifact_row(true);
        session
            .record_tool_call_journaled(row, &table, true)
            .await
            .expect("a tool_call journal-txn fault must fail closed, not abort the turn");
        journal_fault::set_fail_after_artifact_row(false);

        let sid = session.id.to_string();
        assert!(
            db.protected_redaction_history_list(&sid)
                .await
                .unwrap()
                .is_empty(),
            "the rolled-back tool_call journal txn commits no history row"
        );
        assert!(
            db.protected_redaction_artifact_refs_for_artifact(
                RedactionArtifactKind::Tool,
                &event_id.to_string(),
            )
            .await
            .unwrap()
            .is_empty(),
            "no orphan Tool ref survives the atomic rollback"
        );
        let (orig, wire, output) = stored_tool_call_columns(&db, event_id).await;
        for col in [&orig, &wire, &output] {
            assert!(
                !col.contains(ENV_LIT) && !col.contains(CRED_LIT),
                "the seam fallback scrubs every raw literal from the row"
            );
        }
    }

    /// Finding r11-3 (path leak): the journal-failure fallback must scrub EVERY
    /// model/provider-derived column, not just the args/output. Here the secret
    /// lives ONLY in `path` (env), `call_id` (credential), and `parent_call_id`
    /// (env) — the args/output are clean — so the prior fallback (args+output
    /// only) would have left all three raw.
    #[tokio::test]
    async fn trusted_tool_call_audit_row_scrubs_path_and_scalar_columns_on_journal_failure() {
        let db = Db::open_in_memory().unwrap();
        let (session, actor) = faulted_journaling_session(&db).await;
        let table = env_credential_table();
        let event_id = Uuid::new_v4();
        let row = ToolCallRow {
            event_id,
            timestamp: chrono::Utc::now(),
            agent: "Build".to_string(),
            call_id: format!("call-{CRED_LIT}"),
            parent_call_id: Some(format!("parent-{ENV_LIT}")),
            parent_child_index: None,
            identity: crate::session::ToolCallProviderIdentity::default(),
            tool: "read".to_string(),
            mcp_server: None,
            path: Some(format!("/repo/{ENV_LIT}/main.rs")),
            original_input_json: serde_json::json!({ "path": "clean.rs" }),
            wire_input_json: serde_json::json!({ "path": "clean.rs" }),
            recovery: crate::db::tool_calls::Recovery::Clean,
            hard_fail: false,
            exit_code: None,
            sandbox_enabled: false,
            sandboxed: false,
            sandbox_unavailable_reason: None,
            output: "clean output".to_string(),
            truncated: false,
            duration_ms: 5,
            llm_mode: crate::config::extended::LlmMode::default(),
            shape_fingerprint: None,
            hint: None,
        };

        session
            .record_tool_call_journaled(row, &table, true)
            .await
            .unwrap();

        let sid = session.id.to_string();
        assert!(
            db.protected_redaction_history_list(&sid)
                .await
                .unwrap()
                .is_empty(),
            "a faulted journal leaves no history row"
        );
        assert!(
            db.protected_redaction_artifact_refs_for_artifact(
                RedactionArtifactKind::Tool,
                &event_id.to_string(),
            )
            .await
            .unwrap()
            .is_empty(),
            "no orphan Tool ref points at the scrubbed audit row"
        );

        let eid = event_id.to_string();
        let (path, call_id, parent_call_id): (Option<String>, String, Option<String>) = db
            .read(move |conn| {
                let row = conn.query_row(
                    "SELECT path, call_id, parent_call_id FROM tool_call_events WHERE event_id = ?1",
                    [eid],
                    |r| {
                        Ok((
                            r.get::<_, Option<String>>(0)?,
                            r.get::<_, String>(1)?,
                            r.get::<_, Option<String>>(2)?,
                        ))
                    },
                )?;
                Ok(row)
            })
            .await
            .unwrap();
        let path = path.expect("path column persisted");
        assert!(
            !path.contains(ENV_LIT),
            "the `path` column must be scrubbed on journal-failure (finding r11-3)"
        );
        assert!(
            path.contains("[redacted]"),
            "the scrubbed `path` carries the generic placeholder"
        );
        assert!(
            !call_id.contains(CRED_LIT),
            "the `call_id` scalar column must be scrubbed on journal-failure"
        );
        let parent_call_id = parent_call_id.expect("parent_call_id column persisted");
        assert!(
            !parent_call_id.contains(ENV_LIT),
            "the `parent_call_id` column must be scrubbed on journal-failure (finding 4)"
        );
        assert!(
            parent_call_id.contains("[redacted]"),
            "the scrubbed `parent_call_id` carries the generic placeholder"
        );
        shutdown_fake_secure_key_actor(actor).await;
    }

    /// Finding r11-3 (trust source): the audit row's trust MUST come from the
    /// AUTHORING frame (like its co-persisted session event), not the session's
    /// after-turn PRIMARY. Here a TRUSTED model authors the call while the active
    /// PRIMARY is untrusted; both `schedule_dispatch` and `tool_dispatch` derive
    /// `target_trusted` from `SessionEventModelFrame::resolved_trusted()` — the
    /// exact expression the session event resolves — so the event and audit row
    /// stay consistent (both journal), never misclassified by the primary.
    #[tokio::test]
    async fn tool_call_audit_row_trust_reads_authoring_frame_not_after_turn_primary() {
        let tmp = tempfile::tempdir().unwrap();
        // Two providers: an UNTRUSTED primary (`root`) and a TRUSTED authoring /
        // failover model (`openai`).
        let providers = tmp.path().join(".cockpit").join("providers");
        std::fs::create_dir_all(&providers).unwrap();
        std::fs::write(
            tmp.path().join(".cockpit").join("config.json"),
            r#"{"llm_mode":"defensive"}"#,
        )
        .unwrap();
        std::fs::write(
            providers.join("root.json"),
            serde_json::json!({
                "url": "https://example.test/v1",
                "models": [{"id": "root-model", "trust": "untrusted", "mode": "defensive"}],
            })
            .to_string(),
        )
        .unwrap();
        std::fs::write(
            providers.join("openai.json"),
            serde_json::json!({
                "url": "https://example.test/v1",
                "models": [{"id": "gpt-5", "trust": "trusted", "mode": "frontier"}],
            })
            .to_string(),
        )
        .unwrap();
        let db = Db::open_in_memory().unwrap();
        let session = Session::create(
            db.clone(),
            tmp.path().to_path_buf(),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        // The session's active PRIMARY is UNTRUSTED.
        session.set_active_model("root", "root-model").unwrap();
        let config =
            crate::daemon::session_worker::SessionConfigHandle::from_disk_for_tests(tmp.path());
        let table = env_credential_table();

        // The authoring frame is the TRUSTED (failover) model; the primary frame
        // is the untrusted active model.
        let authoring = SessionEventModelFrame {
            provider_id: "openai",
            model_id: "gpt-5",
            config: &config,
            session_table: &table,
        };
        let primary = SessionEventModelFrame {
            provider_id: "root",
            model_id: "root-model",
            config: &config,
            session_table: &table,
        };
        assert!(
            authoring.resolved_trusted(),
            "trust reads the trusted AUTHORING model"
        );
        assert!(
            !primary.resolved_trusted(),
            "the untrusted primary resolves untrusted — reading it would misclassify"
        );

        // The session event journals under the authoring frame.
        let event_data = serde_json::json!({
            "tool": "bash",
            "original_input": { "command": format!("deploy {ENV_LIT}") },
            "wire_input": { "command": format!("deploy {ENV_LIT}") },
            "output": "ok",
        });
        session
            .record_event_with_model_frame(
                SessionEventKind::ToolCall,
                Some("Build"),
                Some("call-x"),
                authoring,
                &event_data,
            )
            .await
            .unwrap();

        // The audit row, derived from the SAME authoring frame's trust + table,
        // ALSO journals — consistent. Reading the untrusted primary would have
        // plain-inserted the raw arg with no history ref.
        let row = audit_row_with_literals("bash", "call-x");
        let event_id = row.event_id;
        session
            .record_tool_call_journaled(row, authoring.session_table, authoring.resolved_trusted())
            .await
            .unwrap();

        let sid = session.id.to_string();
        assert!(
            !db.protected_redaction_history_list(&sid)
                .await
                .unwrap()
                .is_empty(),
            "an authoring-trusted call journals (event + audit consistent)"
        );
        assert!(
            !db.protected_redaction_artifact_refs_for_artifact(
                RedactionArtifactKind::Tool,
                &event_id.to_string(),
            )
            .await
            .unwrap()
            .is_empty(),
            "the audit row journaled a Tool ref — not misclassified by the untrusted primary"
        );
        let (orig, _wire, _output) = stored_tool_call_columns(&db, event_id).await;
        assert!(
            orig.contains(ENV_LIT),
            "the trusted authoring path retains the raw arg locally"
        );
    }
}
