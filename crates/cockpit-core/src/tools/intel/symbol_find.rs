use super::common::*;

// ---- symbol_find -----------------------------------------------------------

pub(in crate::tools::intel) struct SymbolFindTool;

#[async_trait]
impl Tool for SymbolFindTool {
    fn name(&self) -> &str {
        "symbol_find"
    }
    fn description(&self) -> &str {
        "Find symbol definitions by name; use `code` kind `word` for uses and `search`/`grep` for general text"
    }
    fn verbose_description(&self) -> Option<String> {
        Some(
            "Find where a symbol is DEFINED — function, struct, class, method — by name across \
             the indexed codebase, returning the file + line of each definition. Use this to \
             answer \"where is X defined?\" instead of `bash`/`grep`: it returns definitions only, \
             not every mention. Matches `name` as a prefix by default; set `exact` for an exact \
             name and `kind` to narrow. To find every USE of a name instead, use `code` kind `word`."
                .to_string(),
        )
    }
    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "name":   { "type": "string", "description": "Symbol name or prefix" },
                "exact":  { "type": "boolean", "description": "Exact-match toggle (default prefix match)" },
                "kind":   { "type": "string", "description": "Kind filter (function/struct/class/method/...)" }
            },
            "required": ["name"]
        })
    }
    fn verbose_parameters(&self) -> Option<Value> {
        Some(serde_json::json!({
            "type": "object",
            "properties": {
                "name":   { "type": "string", "description": "The symbol name (or, by default, name prefix) to find the definition of" },
                "exact":  { "type": "boolean", "description": "When true, match `name` exactly instead of as a prefix; defaults to prefix matching for discovery" },
                "kind":   { "type": "string", "description": "Optional symbol-kind filter, e.g. `function`, `struct`, `class`, `method`; omit to match any kind" }
            },
            "required": ["name"]
        }))
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let name = args
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_input("`name` is required"))?;
        let exact = args.get("exact").and_then(Value::as_bool).unwrap_or(false);
        let kind = args.get("kind").and_then(Value::as_str);
        let index = index_of(ctx);
        let freshen = index
            .ensure_fresh_scoped(freshen_options(ctx, None))
            .await?;
        let freshen_report = freshen.report().clone();

        let mut hits = index.symbol_find(name, exact, kind).await?;
        if hits.is_empty() {
            // Keep a no-match response independent of the query. Besides
            // avoiding needless prompt echo, this makes an empty scoped index
            // distinguishable from evidence discovered outside the lease.
            return Ok(ToolOutput::text("No matching symbol definitions."));
        }
        // Centrality ranking (additive, default-on, config-disablable):
        // when a name resolves to multiple definitions, surface the most
        // central first; tie-break on the existing (path, line) order. The
        // SET of hits is unchanged — only order — so recall is identical to
        // the disabled path.
        if crate::config::extended::resolve_centrality_ranking(&ctx.cwd) {
            let scores = index.centrality_scores().await?;
            rank_symbol_hits(&mut hits, &scores);
        }
        let mut writer = BudgetedWriter::new(STRUCT_TOKEN_CAP);
        for s in &hits {
            let parent = s
                .parent
                .as_deref()
                .map(|p| format!("{p}."))
                .unwrap_or_default();
            let line = format!("{}:{} {} {parent}{}", s.path, s.line, s.kind, s.name);
            if !write_retained_line(&mut writer, &line) {
                break;
            }
        }
        let mut out = finish(
            &ctx.redact,
            writer,
            "\n... [truncated; narrow with `exact` or `kind`]\n",
        );
        append_freshen_note(&mut out, &freshen_report);
        Ok(out)
    }
}
