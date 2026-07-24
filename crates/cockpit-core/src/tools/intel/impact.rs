use super::common::*;

pub(in crate::tools::intel) enum ImpactSection {
    Callers,
    Calls,
}

pub(in crate::tools::intel) async fn call_impact_section(
    name: &str,
    path: Option<&str>,
    kind: Option<&str>,
    section: ImpactSection,
    ctx: &ToolCtx,
) -> Result<ToolOutput> {
    let path = path.map(|p| rel_path(p, ctx));
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
        let ma = crate::intel::callgraph::rank_multiplier(scores.get(&a.0).copied().unwrap_or(0.0));
        let mb = crate::intel::callgraph::rank_multiplier(scores.get(&b.0).copied().unwrap_or(0.0));
        mb.partial_cmp(&ma).unwrap_or(std::cmp::Ordering::Equal)
    });

    let multi = targets.len() > 1;
    let calls = matches!(section, ImpactSection::Calls)
        .then(|| index.impact_calls(name))
        .transpose()?
        .unwrap_or_default();
    for (tpath, tline, tkind) in &targets {
        if multi {
            writer.writeln(&format!("=== {name} ({tkind}) at {tpath}:{tline} ==="));
        } else {
            writer.writeln(&format!("{name} ({tkind}) at {tpath}:{tline}"));
        }

        if matches!(section, ImpactSection::Callers) {
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
                            "\n... [truncated; narrow the query with `path`/`symbol_kind`]\n",
                        ));
                    }
                }
            }
        }

        if matches!(section, ImpactSection::Calls) {
            if calls.is_empty() {
                writer.writeln("Calls: none");
            } else {
                writer.writeln(&format!("Calls ({}):", calls.len()));
                for (callee, df, dl) in &calls {
                    if !write_retained_line(&mut writer, &format!("  {callee} -> {df}:{dl}")) {
                        return Ok(finish(
                            writer,
                            "\n... [truncated; narrow the query with `path`/`symbol_kind`]\n",
                        ));
                    }
                }
            }
        }
    }
    Ok(finish(
        writer,
        "\n... [truncated; narrow the query with `path`/`symbol_kind`]\n",
    ))
}
