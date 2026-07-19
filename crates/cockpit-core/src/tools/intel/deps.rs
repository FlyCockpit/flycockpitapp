use super::common::*;

// ---- deps ------------------------------------------------------------------

pub struct DepsTool;

#[async_trait]
impl Tool for DepsTool {
    fn name(&self) -> &str {
        "deps"
    }
    fn description(&self) -> &str {
        "Show a file's resolved import dependencies forward/reverse within a hop limit"
    }
    fn defensive_description(&self) -> Option<String> {
        Some(
            "See how one file connects to the rest of the codebase through imports: `forward` = \
             files it depends on, `reverse` = files that depend on it, `both` = both. Use \
             `reverse` to find everything you might break before changing a file — instead of \
             grepping for import lines; imports are resolved through cockpit's index, so this is \
             accurate. `hops` walks the graph that many levels deep (1 = direct neighbours)."
                .to_string(),
        )
    }
    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "path":      { "type": "string", "x-cockpit-kind": "path", "description": "File `path` whose dependencies to walk" },
                "direction": { "type": "string", "description": "forward, reverse, or both (default both)" },
                "hops":      { "type": "integer", "description": "Max hops, 1-10 (default 1)" }
            },
            "required": ["path"]
        })
    }
    fn defensive_parameters(&self) -> Option<Value> {
        Some(serde_json::json!({
            "type": "object",
            "properties": {
                "path":      { "type": "string", "x-cockpit-kind": "path", "description": "Path to the file whose import dependency graph to walk, relative to the project root or absolute" },
                "direction": { "type": "string", "description": "Which way to walk: `forward` (files this one imports), `reverse` (files that import this one), or `both`; defaults to `both`" },
                "hops":      { "type": "integer", "description": "How many levels deep to follow the graph, 1-10; defaults to 1 (direct neighbours only)" }
            },
            "required": ["path"]
        }))
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let path_arg = args
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_input("`path` is required"))?;
        let rel = rel_path(path_arg, ctx);
        let direction = args
            .get("direction")
            .and_then(Value::as_str)
            .unwrap_or("both");
        let hops = args
            .get("hops")
            .and_then(Value::as_u64)
            .map(|h| h.clamp(1, 10) as usize)
            .unwrap_or(1);
        let index = index_of(ctx);
        index.ensure_fresh().await?;

        let edges = index.dep_edges()?;
        // forward: importer → importee; reverse: importee → importer.
        let mut forward: HashMap<&str, Vec<&str>> = HashMap::new();
        let mut reverse: HashMap<&str, Vec<&str>> = HashMap::new();
        let mut unresolved: Vec<&DepEdge> = Vec::new();
        for e in &edges {
            match &e.importee {
                Some(imp) => {
                    forward.entry(&e.importer).or_default().push(imp);
                    reverse.entry(imp).or_default().push(&e.importer);
                }
                None if e.importer == rel => unresolved.push(e),
                None => {}
            }
        }

        let mut writer = BudgetedWriter::new(STRUCT_TOKEN_CAP);
        writer.writeln(&format!("deps for {rel} (hops={hops})"));

        if direction == "forward" || direction == "both" {
            let reached = bfs(&forward, &rel, hops);
            writer.writeln(&format!("forward ({}):", reached.len()));
            for (dist, p) in &reached {
                if !write_retained_line(&mut writer, &format!("  [{dist}] {p}")) {
                    return Ok(finish(writer, "\n... [truncated]\n"));
                }
            }
        }
        if direction == "reverse" || direction == "both" {
            let reached = bfs(&reverse, &rel, hops);
            writer.writeln(&format!("reverse ({}):", reached.len()));
            for (dist, p) in &reached {
                if !write_retained_line(&mut writer, &format!("  [{dist}] {p}")) {
                    return Ok(finish(writer, "\n... [truncated]\n"));
                }
            }
        }
        if !unresolved.is_empty() {
            writer.writeln(&format!("unresolved imports ({}):", unresolved.len()));
            for e in &unresolved {
                if !write_retained_line(&mut writer, &format!("  {}: {}", e.line, e.raw_target)) {
                    break;
                }
            }
        }
        Ok(finish(writer, "\n... [truncated]\n"))
    }
}
