//! The two-stage `docs` pipeline (prompt `docs-agent.md` component C).
//!
//! Invoked by the driver when a caller delegates
//! `task({"intent":"delegate","delegate":{"agent":"docs","prompt":<{package, question}>}})`.
//! To the caller it behaves like a single
//! leaf invocation (GOALS §3a leaf-termination) — the two internal stages
//! are not exposed as delegations.
//!
//! Stage 1 (Docs.1, *resolver*) runs in the **caller's cwd** with the
//! registry tools + `bash`/`webfetch`/`websearch`. It receives **only**
//! the package name (the question never enters its context — token
//! economy, GOALS §10). It confirms/clones the dependency's source into
//! the registry. The resolver tools record the resolved on-disk path in a
//! shared [`crate::tools::docs::DocsResolution`] slot the pipeline reads.
//!
//! Stage 2 (Docs.2, *answerer*) runs in the **resolved package
//! directory** (the cwd-parameterized spawn: we clone the resolver's
//! `SpawnArgs` and override `cwd`) with `read`+`grep`+`glob` only. The
//! pipeline injects the question here. Its final text is the docs tool
//! result surfaced to the caller.
//!
//! If Docs.1 cannot locate/resolve/clone the package, the pipeline
//! returns Docs.1's failure answer and never launches Docs.2 (never
//! hallucinate an answer).

use std::sync::Arc;

use anyhow::Result;
use serde::Deserialize;

use crate::engine::builtin::{SpawnArgs, docs_answerer, docs_resolver};
use crate::engine::driver::run_noninteractive;
use crate::redact::RedactionTable;
use crate::session::Session;
use crate::tools::docs::DocsResolution;

/// Turn cap for the docs resolver (Docs.1). Resolution is narrow work —
/// locate and register the package — so a tighter bound than the
/// answerer's suffices.
const DOCS_RESOLVER_MAX_TURNS: usize = 24;

/// Turn cap for the docs answerer (Docs.2). Answering may require deep
/// read-only exploration of a cloned dependency, so it gets the same
/// headroom as explore.
const DOCS_ANSWERER_MAX_TURNS: usize = 64;

/// The caller → docs structured input. Rides through the existing `task`
/// mechanism as the `prompt` string (JSON). A bare (non-JSON) prompt is
/// tolerated: it's treated as the whole brief, with the first line as the
/// package and the rest as the question — defensive against a weak model
/// that didn't emit JSON (priority #1).
#[derive(Debug, Deserialize)]
struct DocsInput {
    package: String,
    question: String,
}

/// Run the docs pipeline. `brief` is the raw `task` prompt the caller
/// emitted. Returns the answerer's text (or a clear failure answer).
///
/// `approver` + `interrupts` are the driver's real approval channel. They
/// are **not** wired into the two stages' agent loops (those stay
/// noninteractive — `run_noninteractive` gets `None` so the filesystem-
/// confine path raises no escalation, and neither stage carries the
/// `question` tool). They are threaded **only** into Docs.1's `add-package`
/// tool, so cloning a NEW dependency raises a package-add approval — the
/// approval channel is independent of the interactive question/handoff flow
/// (implementation note).
#[allow(clippy::too_many_arguments)]
pub async fn run(
    brief: &str,
    spawn_args: &SpawnArgs,
    session: Arc<Session>,
    locks: Arc<crate::locks::LockManager>,
    redact: Arc<RedactionTable>,
    approver: Option<Arc<crate::approval::Approver>>,
    package_add_interrupts: Arc<crate::engine::interrupt::InterruptHub>,
    cancel: tokio_util::sync::CancellationToken,
    // Model-comparison tandem (shadow) set, forwarded so the resolver +
    // answerer turns are shadowed when the feature is on
    // (implementation note).
    tandem: Option<crate::engine::schedule::TandemSet>,
) -> Result<String> {
    let input = parse_input(brief);

    // The docs pipeline's two stages are leaf agents (`docs-resolver` /
    // `docs-answerer`) — neither carries the `question` tool, so they
    // never raise a human-answer interrupt through their loop. A detached
    // hub satisfies the shared tool-call signature without wiring a client
    // fan-out. The package-add gate is the lone exception: it raises its
    // approval through the driver's REAL `package_add_interrupts` hub, wired
    // directly into the `add-package` tool below.
    let interrupts = Arc::new(crate::engine::interrupt::InterruptHub::detached());

    // ---- Stage 1: resolver, in the caller's cwd, sees only `package`.
    let resolution = DocsResolution::new();
    let resolver = docs_resolver(
        spawn_args,
        resolution.clone(),
        input.package.clone(),
        approver,
        Some(package_add_interrupts),
    );
    // The resolver's brief is ONLY the package name — the question is
    // withheld from its context per the token-economy split.
    let resolver_brief = format!("Package: {}", input.package);
    let resolver_report = run_noninteractive(
        resolver,
        redact.scrub(&resolver_brief),
        session.clone(),
        locks.clone(),
        redact.clone(),
        spawn_args.cwd.clone(),
        interrupts.clone(),
        cancel.clone(),
        // The docs pipeline has no human on the other end (detached hub)
        // and its filesystem reach is the docs hard-deny `confine()` path,
        // which must NOT gain an escalation prompt (sandboxing part 2).
        // No approver → no prompt (and the loop guard, gated on an
        // approver, is inert here; the threshold value is irrelevant).
        None,
        None,
        crate::config::extended::MIN_LOOP_GUARD_THRESHOLD,
        DOCS_RESOLVER_MAX_TURNS,
        tandem.clone(),
    )
    .await?;

    // Did the resolver land a usable, on-disk package?
    let Some(resolved) = resolution.take() else {
        // No package located — return the resolver's own explanation
        // (it already phrases the failure), never spawn Docs.2.
        return Ok(if resolver_report.trim().is_empty() {
            format!("Could not resolve a source repo for `{}`.", input.package)
        } else {
            resolver_report
        });
    };

    // ---- Stage 2: answerer, in the resolved package dir, gets the
    // question. The cwd-parameterized spawn: clone the resolver's
    // SpawnArgs and override only `cwd`.
    let answerer_args = SpawnArgs {
        cwd: resolved.path.clone(),
        ..spawn_args.clone()
    };
    let answerer = docs_answerer(&answerer_args);
    let answerer_brief = format!(
        "Dependency: {} (cwd is its source root)\n\nQuestion: {}",
        resolved.identifier, input.question
    );
    let answer = run_noninteractive(
        answerer,
        redact.scrub(&answerer_brief),
        session,
        locks,
        redact,
        resolved.path,
        interrupts,
        cancel,
        // Docs answerer: hard-deny `confine()` path, no human — no
        // approver / no escalation prompt (sandboxing part 2). Loop guard
        // inert (no approver); the threshold value is irrelevant.
        None,
        None,
        crate::config::extended::MIN_LOOP_GUARD_THRESHOLD,
        DOCS_ANSWERER_MAX_TURNS,
        tandem,
    )
    .await?;
    Ok(answer)
}

/// Parse the structured `{package, question}` input. Falls back to a
/// best-effort split when the prompt isn't JSON (a weaker model may emit
/// plain text): first line = package, remainder = question.
fn parse_input(brief: &str) -> DocsInput {
    if let Ok(parsed) = serde_json::from_str::<DocsInput>(brief.trim()) {
        return parsed;
    }
    // Some models wrap the JSON in prose or fences — try the first
    // balanced object.
    if let Some(start) = brief.find('{')
        && let Some(end) = brief.rfind('}')
        && end > start
        && let Ok(parsed) = serde_json::from_str::<DocsInput>(&brief[start..=end])
    {
        return parsed;
    }
    let mut lines = brief.trim().lines();
    let package = lines.next().unwrap_or("").trim().to_string();
    let question = lines.collect::<Vec<_>>().join("\n").trim().to_string();
    DocsInput { package, question }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_structured_json() {
        let input = parse_input(r#"{"package": "tokio", "question": "multi-thread runtime?"}"#);
        assert_eq!(input.package, "tokio");
        assert_eq!(input.question, "multi-thread runtime?");
    }

    #[test]
    fn parses_json_wrapped_in_fences() {
        let brief = "```json\n{\"package\":\"serde\",\"question\":\"derive?\"}\n```";
        let input = parse_input(brief);
        assert_eq!(input.package, "serde");
        assert_eq!(input.question, "derive?");
    }

    #[test]
    fn falls_back_to_line_split() {
        let input = parse_input("requests\nhow do I post json?");
        assert_eq!(input.package, "requests");
        assert_eq!(input.question, "how do I post json?");
    }
}
