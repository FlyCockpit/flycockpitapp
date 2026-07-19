use super::common::*;

// ---- circular --------------------------------------------------------------

pub struct CircularTool;

#[async_trait]
impl Tool for CircularTool {
    fn name(&self) -> &str {
        "circular"
    }
    fn description(&self) -> &str {
        "Detect import cycles via strongly-connected components of the dependency graph"
    }
    fn defensive_description(&self) -> Option<String> {
        Some(
            "Find import cycles in the codebase: groups of files that depend on each other \
             directly or transitively. Use this when you suspect a circular-dependency problem, \
             or before a refactor that moves code between modules, to see which files are \
             tangled together. Takes no arguments — it analyses the whole project dependency \
             graph and reports each cycle it finds."
                .to_string(),
        )
    }
    fn parameters(&self) -> Value {
        serde_json::json!({ "type": "object", "properties": {} })
    }
    fn defensive_parameters(&self) -> Option<Value> {
        Some(serde_json::json!({ "type": "object", "properties": {} }))
    }

    async fn call(&self, _args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let index = index_of(ctx);
        index.ensure_fresh().await?;
        let edges = index.dep_edges()?;

        // Build the resolved graph (importee NOT NULL).
        let mut nodes: Vec<String> = Vec::new();
        let mut idx: HashMap<String, usize> = HashMap::new();
        let mut adj: Vec<Vec<usize>> = Vec::new();
        let mut seen_edges: HashSet<(usize, usize)> = HashSet::new();
        for e in &edges {
            if let Some(importee) = &e.importee {
                let a = intern(&e.importer, &mut nodes, &mut idx, &mut adj);
                let b = intern(importee, &mut nodes, &mut idx, &mut adj);
                if seen_edges.insert((a, b)) {
                    adj[a].push(b);
                }
            }
        }

        let sccs = tarjan_scc(&adj);
        // Keep cycles only: SCC size > 1, or a self-loop.
        let mut cycles: Vec<Vec<usize>> = Vec::new();
        for comp in sccs {
            if comp.len() > 1 {
                cycles.push(comp);
            } else if comp.len() == 1 {
                let n = comp[0];
                if adj[n].contains(&n) {
                    cycles.push(comp);
                }
            }
        }
        if cycles.is_empty() {
            return Ok(ToolOutput::text("No import cycles found.".to_string()));
        }
        let mut writer = BudgetedWriter::new(STRUCT_TOKEN_CAP);
        writer.writeln(&format!("{} cycle(s):", cycles.len()));
        for comp in &cycles {
            let mut names: Vec<&str> = comp.iter().map(|&i| nodes[i].as_str()).collect();
            names.sort();
            let mut chain = names.clone();
            chain.push(names[0]);
            if !write_retained_line(&mut writer, &format!("  {}", chain.join(" -> "))) {
                break;
            }
        }
        Ok(finish(writer, "\n... [truncated]\n"))
    }
}
