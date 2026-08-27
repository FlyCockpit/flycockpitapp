use super::common::*;

// ---- outline ---------------------------------------------------------------

pub(in crate::tools::intel) struct OutlineTool;

#[async_trait]
impl Tool for OutlineTool {
    fn name(&self) -> &str {
        "outline"
    }
    fn description(&self) -> &str {
        "Show one file's symbols/imports in line order; use `code` kind `tree` for file lists, `context_pack` for overview, `read` for contents"
    }
    fn verbose_description(&self) -> Option<String> {
        Some(
            "Get a structural outline of one file — its functions, types, methods, and imports \
             in source order with line numbers — without reading the whole file. Use this to see \
             a file's shape and jump straight to the right line with a ranged `read`, instead of \
             `cat | head` in `bash` or paging the whole file. Falls back to a regex scan for \
             languages cockpit can't fully parse."
                .to_string(),
        )
    }
    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "path": { "type": "string", "x-cockpit-kind": "path", "description": "File `path` to outline" }
            },
            "required": ["path"]
        })
    }
    fn verbose_parameters(&self) -> Option<Value> {
        Some(serde_json::json!({
            "type": "object",
            "properties": {
                "path": { "type": "string", "x-cockpit-kind": "path", "description": "Path to the single source file to outline, relative to the project root or absolute" }
            },
            "required": ["path"]
        }))
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let path_arg = args
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_input("`path` is required"))?;
        let checked = crate::tools::sandbox::check_native_access(
            ctx,
            &crate::tools::common::resolve(path_arg, &ctx.cwd),
            crate::tools::shell_sandbox::SandboxPathAccess::Read,
        )
        .await?;
        // The gitignore gate canonicalizes/probes this path before choosing
        // whether to prompt, so it is itself the first post-approval host
        // access and must be behind the exact native access fence.
        crate::tools::sandbox::recheck_native_access_effect_boundary(
            &checked,
            crate::tools::shell_sandbox::SandboxPathAccess::Read,
        )
        .await?;
        if let Some(refusal) = crate::tools::sandbox::check_gitignore_read(ctx, &checked).await? {
            return Ok(refusal);
        }
        let rel = rel_path(path_arg, ctx);
        let index = index_of(ctx);
        // `ensure_fresh_scoped` may inspect/index the target.  The initial
        // native approval is not authority across the gitignore/config gates;
        // reclaim the exact checked path at this first host access instead.
        crate::tools::sandbox::recheck_native_access_effect_boundary(
            &checked,
            crate::tools::shell_sandbox::SandboxPathAccess::Read,
        )
        .await?;
        let freshen = index
            .ensure_fresh_scoped(freshen_options(ctx, Some(rel.clone())))
            .await?;
        let freshen_report = freshen.report().clone();

        let (symbols, imports, language) = index.outline_rows(&rel).await?;
        let mut writer = BudgetedWriter::new(STRUCT_TOKEN_CAP);

        // Grammarless / not-indexed language → regex fallback (never errors).
        if language.is_empty() || Language::from_stored(&language).grammar().is_none() {
            // Index refresh is async. Reclaim the exact native path again at
            // the fallback's direct byte-read boundary rather than treating
            // the earlier index fence as ambient authority.
            crate::tools::sandbox::recheck_native_access_effect_boundary(
                &checked,
                crate::tools::shell_sandbox::SandboxPathAccess::Read,
            )
            .await?;
            let body = match std::fs::read_to_string(&checked) {
                Ok(b) => b,
                Err(e) => {
                    return Err(invalid_input(format!("read `{rel}`: {e}")));
                }
            };
            writer.writeln(&format!(
                "{rel} (unknown language — regex outline, may be incomplete)"
            ));
            let hits = regex_outline(&body);
            if hits.is_empty() {
                writer.writeln("  (no definitions matched)");
            }
            for (name, line) in hits {
                if !write_retained_line(&mut writer, &format!("  {line}: {name}")) {
                    break;
                }
            }
            let mut out = finish(writer, "\n... [truncated]\n");
            append_freshen_note(&mut out, &freshen_report);
            return Ok(out);
        }

        writer.writeln(&format!("{rel} ({language})"));
        if !imports.is_empty() {
            writer.writeln("imports:");
            for (target, line) in &imports {
                if !write_retained_line(&mut writer, &format!("  {line}: {target}")) {
                    let mut out = finish(writer, "\n... [truncated]\n");
                    append_freshen_note(&mut out, &freshen_report);
                    return Ok(out);
                }
            }
        }
        if !symbols.is_empty() {
            writer.writeln("symbols:");
            for s in &symbols {
                let vis = s
                    .visibility
                    .as_deref()
                    .map(|v| format!("{v} "))
                    .unwrap_or_default();
                let parent = s
                    .parent
                    .as_deref()
                    .map(|p| format!("{p}."))
                    .unwrap_or_default();
                let span = if s.end_line > s.line {
                    format!("{}-{}", s.line, s.end_line)
                } else {
                    s.line.to_string()
                };
                // Prefer the captured signature (first source line) for
                // callables; fall back to the synthesized form otherwise.
                let sig = match (s.kind.as_str(), &s.signature) {
                    ("function" | "method", Some(sig)) if !sig.is_empty() => {
                        format!("{vis}{}", sig.trim())
                    }
                    _ => format!("{vis}{} {parent}{}", s.kind, s.name),
                };
                if !write_retained_line(&mut writer, &format!("  {span}: {sig}")) {
                    break;
                }
            }
        }
        if symbols.is_empty() && imports.is_empty() {
            writer.writeln("  (no symbols or imports)");
        }
        let mut out = finish(writer, "\n... [truncated]\n");
        append_freshen_note(&mut out, &freshen_report);
        Ok(out)
    }
}
