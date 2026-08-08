//! AC6 `built_in_and_monty_sealed_reference_matrix`
//!
//! Every built-in and Monty sealed-use path accepts only
//! `{sealed_value_id, action_id, bounded_params}`. Untrusted Defensive /
//! Normal / Frontier callers cannot receive a literal; trusted callers follow
//! `ModelTrust` raw inference custody **without** gaining a literal-returning
//! tool API.
//!
//! Two tests, and the split is deliberate:
//!
//! - [`built_in_and_monty_use_paths_return_no_literal`] *invokes* both
//!   model-facing entry points for real — `Tool::call` for the built-in path
//!   and `crate::mcp::builtin::invoke` for the Monty path — and asserts the
//!   action ran, saw the literal, and that the literal reached neither
//!   caller. This is the test that can actually fail if the reference-only
//!   rendering breaks.
//! - [`built_in_and_monty_sealed_reference_matrix`] covers the schema and
//!   structural properties around those paths. It inspects definitions rather
//!   than driving them, which is the appropriate shape for "no such API
//!   exists" claims but cannot substitute for invoking the paths.

use std::sync::Arc;

use super::*;
use crate::config::extended::LlmMode;
use crate::config::providers::ModelTrust;
use crate::engine::tool::Tool;
use crate::sealed::custody::{ALL_LLM_MODES, ALL_MODEL_TRUSTS};
use crate::sealed::runtime::{RecordingRedactionSink, SealedRuntime};
use crate::sealed::store::IssueSealedGrant;
use crate::sealed::{
    SEALED_USE_DENIED_MESSAGE, SealedActionId, SealedActionRevision, SealedCustodyRequest,
    USE_SEALED_VALUE_ARG_KEYS, USE_SEALED_VALUE_TOOL, UseSealedValueRequest,
    parse_use_sealed_value_args, use_sealed_value_schema,
};
use crate::tools::use_sealed_value::UseSealedValueTool;

/// Drive both model-facing sealed-use entry points end to end.
///
/// The action under test reads the literal through its handle, so a passing
/// run proves the value really was resolved and used — the caller getting no
/// literal is a property of the *rendering*, not an artifact of the use
/// having been denied. That distinction is why this test asserts
/// `probe.saw_literal()` alongside the negative assertions: without it, a
/// blanket denial would satisfy every "no literal" check vacuously.
#[tokio::test]
async fn built_in_and_monty_use_paths_return_no_literal() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (mut ctx, db) = crate::tools::common::test_ctx_with_db(tmp.path());

    // A *live redaction table* is a precondition of using a sealed value, not
    // a convenience. `SessionRedactionSink::register_before_use` fails closed
    // when the hub owns none, because releasing a literal to an action while
    // egress is unscrubbed is the exact window the redaction-before-use
    // ordering exists to close. `test_ctx` installs a **detached** hub
    // (`InterruptHub::detached()` sets `redaction: None`), so a tool call made
    // against the default test context is denied at that step — after
    // authorization and after the grant claim, but before the action runs.
    // Install a real hub so this test exercises the permitted path.
    let (events, _events_rx) = tokio::sync::broadcast::channel(16);
    let redaction = Arc::new(std::sync::RwLock::new(Arc::new(
        crate::redact::RedactionTable::empty(),
    )));
    ctx.interrupts = Arc::new(crate::engine::interrupt::InterruptHub::new(
        events,
        redaction,
        Arc::new(std::sync::atomic::AtomicUsize::new(1)),
        db.clone(),
        ctx.session.id,
    ));

    // The tool reads workspace trust live and fails closed, so a use can only
    // reach the action if the project is genuinely trusted.
    ctx.session
        .db
        .set_workspace_trust(
            &ctx.session.project_root,
            cockpit_db::db::workspace_trust::WorkspaceTrustMode::Trust,
        )
        .await
        .expect("workspace trusted");

    let compartment = SealedCompartment::at(tmp.path().join("sealed-compartment.json"));
    let directory = SealedValueDirectory::new(ctx.session.db.clone(), compartment.clone());
    let project_key = SealedProjectKey::from_canonical(ctx.session.project_id.clone());
    let seeded = directory
        .create(
            SealedFixture::owner(),
            CreateSealedValue {
                scope: SealedScopeRef::Project(project_key.clone()),
                name: SealedName::canonical("deploy_token").expect("name"),
                description: SealedDescription::parse("deployment credential")
                    .expect("description"),
                owner_principal: "owner".to_string(),
            },
            SealedLiteral::new(TEST_LITERAL),
            1_000,
        )
        .await
        .expect("seeded sealed value");

    // Every grant axis is taken from the *real* context, so the grant the
    // production path looks up is the one under test.
    directory
        .issue_action_grant(
            SealedFixture::owner(),
            IssueSealedGrant {
                record_id: seeded.record_id,
                value_version: 1,
                project_key,
                session_id: ctx.session.id,
                session_generation: ctx.config.generation(),
                action_id: SealedActionId::parse(PROBE_ACTION).expect("action id"),
                action_revision: SealedActionRevision::new(1).expect("revision"),
                issued_at_ms: 1_000,
                expires_at_ms: None,
            },
        )
        .await
        .expect("grant issued");

    let probe = Arc::new(ProbeAction::new(1));
    let runtime = Arc::new(SealedRuntime::new(
        ctx.session.db.clone(),
        compartment,
        registry_with(vec![probe.clone() as Arc<dyn SealedHostAction>]),
    ));

    let args = serde_json::json!({
        "sealed_value_id": seeded.record_id.to_string(),
        "action_id": PROBE_ACTION,
        "parameters": [
            { "name": "label", "text": "primary" },
            { "name": "retries", "number": 2 }
        ]
    });

    // ---- Built-in path: the real `Tool::call`. ----
    let built_in = UseSealedValueTool::with_runtime(runtime.clone());
    let output = built_in
        .call(args.clone(), &ctx)
        .await
        .expect("built-in sealed use");
    assert_eq!(
        probe.invocations(),
        1,
        "the built-in path reached the action"
    );
    assert_eq!(
        probe.saw_literal().as_deref(),
        Some(TEST_LITERAL),
        "the action really did resolve the literal, so the caller-side \
         assertions below are not vacuous"
    );
    assert!(
        output.content.contains("outcome"),
        "the declared safe projection is returned: {}",
        output.content
    );
    assert!(
        !output.content.contains(TEST_LITERAL),
        "the built-in path must never render the literal: {}",
        output.content
    );
    // Redaction-before-use actually happened, and durably: the action only
    // ran because the literal was registered and the table persisted first.
    let persisted = ctx
        .session
        .persisted_redaction_table()
        .expect("redaction table read")
        .expect("a sealed use persists the redaction table");
    assert!(
        !persisted.scrub(TEST_LITERAL).contains(TEST_LITERAL),
        "the sealed literal is scrubbed by the session's persisted table"
    );

    // ---- Monty path: the real builtin dispatch, same tool definition. ----
    let registry = Arc::new(crate::mcp::builtin::BuiltinRegistry::from_functions(vec![
        crate::mcp::builtin::ToolOutputBuiltinAdapter::new(Arc::new(
            UseSealedValueTool::with_runtime(runtime.clone()),
        ) as Arc<dyn Tool>)
        .into_function()
        .expect("the sealed use tool adapts onto the Monty builtin surface"),
    ]));
    let host =
        crate::mcp::builtin::HostContext::from_tool_ctx(&ctx).with_builtin_registry(registry);
    let monty = crate::mcp::builtin::invoke(&host, USE_SEALED_VALUE_TOOL, args.clone())
        .await
        .expect("monty sealed use");
    let monty_rendered = monty.to_string();
    assert_eq!(probe.invocations(), 2, "the Monty path reached the action");
    assert!(
        monty_rendered.contains("outcome"),
        "the Monty path returns the same declared projection: {monty_rendered}"
    );
    assert!(
        !monty_rendered.contains(TEST_LITERAL),
        "the Monty path must never render the literal: {monty_rendered}"
    );

    // ---- Negative: a value the caller holds no grant for denies through
    // both paths, with the one content-free message and no literal. ----
    let ungranted = serde_json::json!({
        "sealed_value_id": uuid::Uuid::new_v4().to_string(),
        "action_id": PROBE_ACTION,
        "parameters": [
            { "name": "label", "text": "primary" },
            { "name": "retries", "number": 2 }
        ]
    });
    let denied = built_in
        .call(ungranted.clone(), &ctx)
        .await
        .expect("a denied use still returns a rendered output");
    assert_eq!(
        probe.invocations(),
        2,
        "an ungranted value must not reach the action at all"
    );
    assert_eq!(
        denied.content, SEALED_USE_DENIED_MESSAGE,
        "denial is the single content-free message"
    );
    let monty_denied = crate::mcp::builtin::invoke(&host, USE_SEALED_VALUE_TOOL, ungranted)
        .await
        .expect("monty denied use");
    assert!(
        monty_denied.to_string().contains(SEALED_USE_DENIED_MESSAGE),
        "the Monty path renders the same denial: {monty_denied}"
    );
    assert_eq!(probe.invocations(), 2);
}

#[tokio::test]
async fn built_in_and_monty_sealed_reference_matrix() {
    // =====================================================================
    // The one shared schema, used by both the built-in and the Monty path.
    // =====================================================================
    let tool = UseSealedValueTool::new();
    assert_eq!(tool.name(), USE_SEALED_VALUE_TOOL);
    assert_eq!(
        tool.parameters(),
        use_sealed_value_schema(),
        "the built-in tool and the shared schema are one definition"
    );

    let schema = use_sealed_value_schema();
    let properties = schema["properties"]
        .as_object()
        .expect("schema declares properties");
    let mut keys: Vec<_> = properties.keys().map(String::as_str).collect();
    keys.sort();
    let mut expected = USE_SEALED_VALUE_ARG_KEYS.to_vec();
    expected.sort();
    assert_eq!(keys, expected, "exactly three arguments, and only these");
    assert_eq!(
        schema["additionalProperties"],
        serde_json::Value::Bool(false),
        "no additional argument may be smuggled in"
    );
    // The wire schema carries no destination field. It does not need a
    // denylist to say so: the only three keys are an opaque value id, an
    // opaque action id, and a parameter bag whose contents are validated
    // against the action's closed parameter types before anything else runs.
    for forbidden in [
        "endpoint",
        "url",
        "uri",
        "host",
        "command",
        "cmd",
        "env",
        "environment",
        "header",
        "headers",
        "template",
        "request",
        "body",
        "script",
        "path",
        "projection",
        "output",
    ] {
        assert!(
            !properties.contains_key(forbidden),
            "the use schema must never accept `{forbidden}`"
        );
    }

    // Monty reaches native tools through the same `Tool` definition, so the
    // Monty surface cannot drift from the built-in one.
    assert!(
        crate::engine::tool::is_monty_builtin_adaptable(USE_SEALED_VALUE_TOOL),
        "the sealed use tool is reachable from Monty through its own definition"
    );
    crate::mcp::builtin::ToolOutputBuiltinAdapter::new(Arc::new(UseSealedValueTool::new()))
        .into_function()
        .expect("the sealed use tool adapts onto the Monty builtin surface");
    // The adapter derives its Monty schema from the tool's own
    // `parameters()`, so the Monty argument surface *is* the built-in one.
    let adapter_source = include_str!("../../mcp/builtin.rs");
    let adapter_at = adapter_source
        .find("pub fn into_function(self)")
        .expect("adapter builds its function");
    let adapter_body = &adapter_source[adapter_at..adapter_at + 1_200];
    assert!(
        adapter_body.contains("normal.parameters") && adapter_body.contains("defensive.parameters"),
        "the Monty adapter reuses the tool's own declared parameters"
    );

    // =====================================================================
    // Argument parsing: a closed array of typed entries, never an open map.
    // =====================================================================
    let good = serde_json::json!({
        "sealed_value_id": uuid::Uuid::new_v4().to_string(),
        "action_id": PROBE_ACTION,
        "parameters": [
            { "name": "label", "text": "primary" },
            { "name": "retries", "number": 2 },
            { "name": "dry_run", "flag": true }
        ]
    });
    let parsed = parse_use_sealed_value_args(&good).expect("closed typed entries parse");
    assert_eq!(parsed.parameters.len(), 3);

    for bad in [
        // An undeclared top-level key.
        serde_json::json!({
            "sealed_value_id": uuid::Uuid::new_v4().to_string(),
            "action_id": PROBE_ACTION,
            "parameters": [],
            "endpoint": "https://exfil.example"
        }),
        // A nested object — the shape a request template would need. There is
        // no entry key it can arrive under.
        serde_json::json!({
            "sealed_value_id": uuid::Uuid::new_v4().to_string(),
            "action_id": PROBE_ACTION,
            "parameters": [{ "name": "request", "url": "https://exfil.example" }]
        }),
        // The retired open-map form no longer parses at all.
        serde_json::json!({
            "sealed_value_id": uuid::Uuid::new_v4().to_string(),
            "action_id": PROBE_ACTION,
            "parameters": { "headers": "Authorization: Bearer x" }
        }),
        // Two values in one entry is ambiguous and refused.
        serde_json::json!({
            "sealed_value_id": uuid::Uuid::new_v4().to_string(),
            "action_id": PROBE_ACTION,
            "parameters": [{ "name": "label", "text": "primary", "number": 1 }]
        }),
    ] {
        assert!(
            parse_use_sealed_value_args(&bad).is_err(),
            "a caller-supplied destination must be rejected: {bad}"
        );
    }

    // Strict-wire: the schema declares no open object anywhere, which is what
    // makes the closed parameter model visible on the wire and not just in
    // Rust types.
    assert_eq!(
        schema["properties"]["parameters"]["items"]["additionalProperties"],
        serde_json::Value::Bool(false),
        "the parameter entry schema must be closed"
    );

    // =====================================================================
    // Untrusted callers, every mode: reference-only, and the use path yields
    // no literal.
    // =====================================================================
    let fixture = SealedFixture::new().await;
    let seeded = fixture
        .seed_value(
            SealedScopeRef::Project(fixture.project_key.clone()),
            "deploy_token",
        )
        .await;
    let probe = Arc::new(ProbeAction::new(1));
    let runtime = SealedRuntime::new(
        fixture.db.clone(),
        fixture.compartment.clone(),
        registry_with(vec![probe.clone() as Arc<dyn SealedHostAction>]),
    );

    for (index, mode) in ALL_LLM_MODES.into_iter().enumerate() {
        let generation = 100 + index as u64;
        fixture
            .directory()
            .issue_action_grant(
                SealedFixture::owner(),
                IssueSealedGrant {
                    record_id: seeded.record_id,
                    value_version: 1,
                    project_key: fixture.project_key.clone(),
                    session_id: fixture.session_id,
                    session_generation: generation,
                    action_id: SealedActionId::parse(PROBE_ACTION).expect("action id"),
                    action_revision: SealedActionRevision::new(1).expect("revision"),
                    issued_at_ms: 1_000,
                    expires_at_ms: None,
                },
            )
            .await
            .expect("grant issued");

        let mut ctx = use_context(&fixture, generation, 20_000);
        ctx.caller_trust = ModelTrust::Untrusted;
        ctx.caller_mode = mode;

        assert!(
            SealedCustodyRequest::new(ctx.caller_trust, ctx.caller_mode)
                .custody()
                .is_reference_only(),
            "an untrusted {mode:?} caller is reference-only"
        );

        let sink = RecordingRedactionSink::new();
        let projection = runtime
            .use_sealed_value(
                &UseSealedValueRequest {
                    sealed_value_id: seeded.record_id,
                    action_id: SealedActionId::parse(PROBE_ACTION).expect("action id"),
                    parameters: valid_params(),
                },
                &ctx,
                &sink,
                &crate::sealed::runtime::FixedProjectTrust(SealedProjectTrust::Trusted),
            )
            .await
            .expect("reference-only use succeeds for an untrusted caller");

        let rendered = format!("{projection:?}");
        assert!(
            !rendered.contains(TEST_LITERAL),
            "an untrusted {mode:?} caller must never receive the literal"
        );
    }

    // =====================================================================
    // Trusted callers gain no literal-returning tool API.
    // =====================================================================
    for mode in ALL_LLM_MODES {
        assert!(
            SealedCustodyRequest::new(ModelTrust::Trusted, mode)
                .custody()
                .permits_raw_literal(),
            "a trusted {mode:?} caller keeps its ordinary raw inference custody"
        );
    }
    // …but the tool surface is identical for both, and there is no sibling
    // tool that returns a literal.
    let sealed_named_tools: Vec<&str> = crate::engine::builtin::known_agent_tool_names()
        .iter()
        .copied()
        .filter(|name| name.contains("sealed"))
        .collect();
    assert_eq!(
        sealed_named_tools,
        vec![USE_SEALED_VALUE_TOOL],
        "there is exactly one sealed tool, and it is the reference-only one"
    );

    // =====================================================================
    // Structural: no sealed surface returns a literal publicly.
    // =====================================================================
    for (label, source) in [
        ("runtime", include_str!("../runtime.rs")),
        ("store", include_str!("../store.rs")),
        ("grant", include_str!("../grant.rs")),
        ("marker", include_str!("../marker.rs")),
        ("tool", include_str!("../../tools/use_sealed_value.rs")),
    ] {
        for line in source.lines() {
            let trimmed = line.trim_start();
            if !(trimmed.starts_with("pub fn ") || trimmed.starts_with("pub async fn ")) {
                continue;
            }
            assert!(
                !trimmed.contains("-> SealedLiteral")
                    && !trimmed.contains("Result<SealedLiteral")
                    && !trimmed.contains("Option<SealedLiteral"),
                "`{label}` must expose no public literal-returning API: {trimmed}"
            );
        }
    }

    // The agent-facing Monty sealed lifecycle builtins are gone entirely, so
    // there is no sealed write path and no created/overwritten status branch
    // for an untrusted caller to probe.
    let monty_source = include_str!("../../mcp/builtin.rs");
    let monty_production = monty_source
        .split("\nmod tests {")
        .next()
        .expect("production module precedes tests");
    for retired in [
        "\"set_sealed_value\"",
        "\"request_sealed_value\"",
        "store_sealed_value",
        "\"overwritten\"",
    ] {
        assert!(
            !monty_production.contains(retired),
            "the retired agent-facing sealed surface `{retired}` must not return"
        );
    }
    assert!(
        monty_production.contains("UseSealedValueTool"),
        "Monty reaches sealed values only through the sanctioned mechanism"
    );

    // =====================================================================
    // The built-in tool renders the single content-free denial.
    // =====================================================================
    assert_eq!(
        crate::tools::use_sealed_value::denial_text(),
        SEALED_USE_DENIED_MESSAGE
    );
    assert!(
        tool.description().len() <= 220,
        "the model-facing description stays terse"
    );
    for forbidden in ["endpoint", "command", "header", "template"] {
        assert!(
            !tool.description().contains(forbidden),
            "the terse description must not advertise a destination concept"
        );
    }
    let defensive = tool
        .defensive_description()
        .expect("defensive steering exists");
    assert!(
        defensive.contains("cannot supply an endpoint"),
        "defensive prose states the closed-reference rule outright"
    );
    // Mode selects prose only; the schema is identical across modes.
    for mode in ALL_LLM_MODES {
        let definition = crate::engine::tool::definition_of(&tool as &dyn Tool, mode, None);
        assert_eq!(
            definition.parameters,
            use_sealed_value_schema(),
            "the sealed use schema never varies by mode"
        );
    }
    let _ = ALL_MODEL_TRUSTS;
    let _ = LlmMode::default();
}
