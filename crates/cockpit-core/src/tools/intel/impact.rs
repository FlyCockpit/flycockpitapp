use super::common::*;

// ---- impact ----------------------------------------------------------------

pub struct ImpactTool;

#[async_trait]
impl Tool for ImpactTool {
    fn name(&self) -> &str {
        "impact"
    }
    fn description(&self) -> &str {
        "Show one symbol's callers and body calls; for the blast radius of your current git diff, use `change_impact`"
    }
    fn defensive_description(&self) -> Option<String> {
        Some(
            "Get the call-graph context of one symbol in a single call: its CALLERS (who calls \
             it, with file:line) and its CALLS (what its own body invokes, each resolved to a \
             definition's file:line). Use this to find the blast radius before you rename or \
             change a function — instead of grepping for the name and reading every hit. Only \
             high-confidence edges are shown: a call is reported when its name resolves to \
             exactly ONE definition; ambiguous or unresolved calls are omitted, never guessed. \
             Disambiguate with `path`/`kind` if the name is defined in several files."
                .to_string(),
        )
    }
    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "x-cockpit-primary-field": "name",
            "properties": {
                "name": { "type": "string", "x-cockpit-aliases": ["symbol", "function", "fn"], "description": "Symbol name to analyze" },
                "path": { "type": "string", "x-cockpit-kind": "path", "description": "Defining file `path` filter when the name is ambiguous" },
                "kind": { "type": "string", "description": "Kind filter (function/struct/class/method/...)" }
            },
            "required": ["name"]
        })
    }
    fn defensive_parameters(&self) -> Option<Value> {
        Some(serde_json::json!({
            "type": "object",
            "x-cockpit-primary-field": "name",
            "properties": {
                "name": { "type": "string", "x-cockpit-aliases": ["symbol", "function", "fn"], "description": "The exact symbol name whose callers and calls to report" },
                "path": { "type": "string", "x-cockpit-kind": "path", "description": "Optional defining-file path to disambiguate when the name is defined in several files, relative to the project root or absolute" },
                "kind": { "type": "string", "description": "Optional symbol-kind filter, e.g. `function`, `struct`, `method`; omit to match any kind" }
            },
            "required": ["name"]
        }))
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let name = args
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_input("`name` is required"))?;
        let path = args
            .get("path")
            .and_then(Value::as_str)
            .map(|p| rel_path(p, ctx));
        let kind = args.get("kind").and_then(Value::as_str);
        let index = index_of(ctx);
        index.ensure_fresh().await?;

        let targets = index.impact_targets(name, path.as_deref(), kind)?;
        if targets.is_empty() {
            return Ok(ToolOutput::text(format!("No symbol matches `{name}`.")));
        }

        let mut writer = BudgetedWriter::new(STRUCT_TOKEN_CAP);
        // When the name still resolves to multiple definitions, report
        // each target's context separately (most-central first) so the
        // model isn't forced to disambiguate up front.
        let scores = index.centrality_scores()?;
        let mut targets = targets;
        targets.sort_by(|a, b| {
            let ma =
                crate::intel::callgraph::rank_multiplier(scores.get(&a.0).copied().unwrap_or(0.0));
            let mb =
                crate::intel::callgraph::rank_multiplier(scores.get(&b.0).copied().unwrap_or(0.0));
            mb.partial_cmp(&ma).unwrap_or(std::cmp::Ordering::Equal)
        });

        let multi = targets.len() > 1;
        let calls = index.impact_calls(name)?;
        for (tpath, tline, tkind) in &targets {
            if multi {
                writer.writeln(&format!("=== {name} ({tkind}) at {tpath}:{tline} ==="));
            } else {
                writer.writeln(&format!("{name} ({tkind}) at {tpath}:{tline}"));
            }

            let callers = index.impact_callers(tpath, *tline)?;
            if callers.is_empty() {
                writer.writeln("Callers: none");
            } else {
                writer.writeln(&format!("Callers ({}):", callers.len()));
                for (cf, cl, csym) in &callers {
                    let sym = csym
                        .as_deref()
                        .map(|s| format!(" in {s}"))
                        .unwrap_or_default();
                    if !write_retained_line(&mut writer, &format!("  {cf}:{cl}{sym}")) {
                        return Ok(finish(
                            writer,
                            "\n... [truncated; narrow the query with `path`/`kind`]\n",
                        ));
                    }
                }
            }

            if calls.is_empty() {
                writer.writeln("Calls: none");
            } else {
                writer.writeln(&format!("Calls ({}):", calls.len()));
                for (callee, df, dl) in &calls {
                    if !write_retained_line(&mut writer, &format!("  {callee} -> {df}:{dl}")) {
                        return Ok(finish(
                            writer,
                            "\n... [truncated; narrow the query with `path`/`kind`]\n",
                        ));
                    }
                }
            }
        }
        Ok(finish(
            writer,
            "\n... [truncated; narrow the query with `path`/`kind`]\n",
        ))
    }
}
