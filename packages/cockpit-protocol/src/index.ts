import { z } from "zod";

export const PROTOCOL_VERSION = 1 as const;

export const uuidSchema = z.string().uuid();
export const requestIdSchema = uuidSchema;
export const sessionIdSchema = uuidSchema;
export const projectRootSchema = z.string().trim().min(1).max(4096);

const optionalStringSchema = z.string().min(1).optional();
const optionalUuidSchema = uuidSchema.nullable().optional();
const passthroughObjectSchema = z.object({}).passthrough();
const statsRangeSchema = z.enum(["last7_days", "all_time"]);
const envDriftPolicySchema = z.enum(["daemon", "client", "update-daemon", "error-on-drift"]);
const activeModelSwitchTriggerSchema = z.enum(["picker", "quick", "cycle", "daemon"]);

export const grantKindSchema = z.enum(["command", "path", "mcp_tool"]);
export type GrantKind = z.infer<typeof grantKindSchema>;

export const interruptOptionSchema = z
  .object({
    id: z.string().min(1),
    label: z.string().min(1),
    description: z.string().optional(),
    secondary: z.boolean().optional(),
  })
  .passthrough();
export type InterruptOption = z.infer<typeof interruptOptionSchema>;

export const commandDetailSchema = z
  .object({
    full_command: z.string(),
    highlight: z
      .object({ start: z.number().int().nonnegative(), end: z.number().int().nonnegative() })
      .optional(),
    step: z.number().int().nonnegative(),
    step_count: z.number().int().nonnegative(),
    cwd: z.string().optional(),
    remembered_key: z.string().optional(),
    write_content: z.object({ content: z.string(), dynamic: z.boolean().optional() }).optional(),
    risk_tier: z.string().optional(),
    risk_reasons: z.array(z.string()).optional(),
    affected_targets: z.array(z.string()).optional(),
    native_tool_hints: z.array(z.string()).optional(),
    offered_scopes: z.array(z.string()).optional(),
    policy_cap: z.string().optional(),
  })
  .passthrough();
export type CommandDetail = z.infer<typeof commandDetailSchema>;

export const sandboxDenialEvidenceSchema = z
  .object({
    kind: z.string().min(1),
    data: z.unknown().optional(),
  })
  .passthrough();
export const sandboxDenialReportSchema = z
  .object({
    confidence: z.enum(["high", "possible"]),
    evidence: z.array(sandboxDenialEvidenceSchema),
  })
  .passthrough();
export const sandboxEscalationSchema = z
  .object({
    confined_exit: z.number().int(),
    confined_stderr: z.string(),
    suggested_paths: z.array(z.string()).optional(),
    suggested_access: z.string().optional(),
    denial: sandboxDenialReportSchema.optional(),
  })
  .passthrough();
export type SandboxEscalation = z.infer<typeof sandboxEscalationSchema>;

export const interruptQuestionSchema = z.discriminatedUnion("kind", [
  z
    .object({
      kind: z.literal("single"),
      data: z
        .object({
          prompt: z.string(),
          options: z.array(interruptOptionSchema),
          allow_freetext: z.boolean().optional(),
          command_detail: commandDetailSchema.optional(),
          permission: z.boolean().optional(),
          approval_class: grantKindSchema.optional(),
          sandbox_escalation: sandboxEscalationSchema.optional(),
        })
        .passthrough(),
    })
    .passthrough(),
  z
    .object({
      kind: z.literal("multi"),
      data: z
        .object({
          prompt: z.string(),
          options: z.array(interruptOptionSchema),
          allow_freetext: z.boolean().optional(),
        })
        .passthrough(),
    })
    .passthrough(),
  z
    .object({
      kind: z.literal("freetext"),
      data: z.object({ prompt: z.string(), masked: z.boolean().optional() }).passthrough(),
    })
    .passthrough(),
]);
export type InterruptQuestion = z.infer<typeof interruptQuestionSchema>;

type ResolveResponseValue =
  | { kind: "single"; data: { selected_id: string } }
  | { kind: "multi"; data: { selected_ids: string[] } }
  | { kind: "freetext"; data: { text: string } }
  | { kind: "batch"; data: { responses: ResolveResponseValue[] } }
  | { kind: "cancel" };

export const resolveResponseSchema: z.ZodType<ResolveResponseValue> = z.lazy(() =>
  z.union([
    z
      .object({
        kind: z.literal("single"),
        data: z.object({ selected_id: z.string().min(1) }).passthrough(),
      })
      .passthrough(),
    z
      .object({
        kind: z.literal("multi"),
        data: z.object({ selected_ids: z.array(z.string().min(1)) }).passthrough(),
      })
      .passthrough(),
    z
      .object({ kind: z.literal("freetext"), data: z.object({ text: z.string() }).passthrough() })
      .passthrough(),
    z
      .object({
        kind: z.literal("batch"),
        data: z.object({ responses: z.array(resolveResponseSchema) }).passthrough(),
      })
      .passthrough(),
    z.object({ kind: z.literal("cancel") }).passthrough(),
  ]),
);
export type ResolveResponse = z.infer<typeof resolveResponseSchema>;

const requestParamSchemas = {
  archive_session: z.object({ session_id: uuidSchema, cascade: z.boolean().optional() }).strict(),
  attach: z
    .object({
      session_id: optionalUuidSchema,
      since_seq: z.number().int().nonnegative().optional(),
      project_root: z.string().optional(),
      no_sandbox: z.boolean().optional(),
      interactive: z.boolean().optional(),
      model_override: z.string().optional(),
      client_protocol_version: z.number().int().nonnegative().optional(),
      env_snapshot: z.unknown().optional(),
      env_policy: envDriftPolicySchema.optional(),
    })
    .strict(),
  cancel_paused_work: z.object({ session_id: uuidSchema }).strict(),
  delete_session: z.object({ session_id: uuidSchema, cascade: z.boolean().optional() }).strict(),
  fork_session: z
    .object({
      parent_session_id: uuidSchema,
      fork_point_turn_id: z.string().nullable().optional(),
      ephemeral: z.boolean().optional(),
    })
    .strict(),
  fs_create_dir: z.object({ project_root: projectRootSchema, path: z.string() }).strict(),
  fs_delete: z.object({ project_root: projectRootSchema, path: z.string() }).strict(),
  fs_list: z
    .object({
      project_root: projectRootSchema,
      path: z.string(),
      show_hidden: z.boolean().optional(),
    })
    .strict(),
  fs_read: z
    .object({ project_root: projectRootSchema, path: z.string(), base64: z.boolean().optional() })
    .strict(),
  fs_rename: z
    .object({ project_root: projectRootSchema, from_path: z.string(), to_path: z.string() })
    .strict(),
  fs_stat: z.object({ project_root: projectRootSchema, path: z.string() }).strict(),
  fs_write: z
    .object({
      project_root: projectRootSchema,
      path: z.string(),
      content: z.string(),
      base_hash: z.string().optional(),
    })
    .strict(),
  git_diff_file: z.object({ project_root: projectRootSchema, path: z.string() }).strict(),
  git_status: z.object({ project_root: projectRootSchema }).strict(),
  list_sessions: z
    .object({ project_id: z.string().nullable().optional(), parent_session_id: optionalUuidSchema })
    .strict(),
  read_history_page: z
    .object({
      session_id: uuidSchema,
      before_seq: z.number().int().nonnegative().nullable().optional(),
      limit: z.number().int().positive(),
    })
    .strict(),
  read_session_messages: z
    .object({
      session_id: uuidSchema,
      before_seq: z.number().int().nonnegative().nullable().optional(),
      limit: z.number().int().positive(),
    })
    .strict(),
  rename_session: z.object({ session_id: uuidSchema, title: z.string().min(1).max(240) }).strict(),
  resolve_interrupt: z
    .object({ interrupt_id: uuidSchema, response: resolveResponseSchema })
    .strict(),
  resume_paused_work: z.object({ session_id: uuidSchema }).strict(),
  send_user_message: z
    .object({
      text: z.string(),
      display_text: optionalStringSchema,
      tag_expansions: z.array(passthroughObjectSchema).optional(),
      image_refs: z.array(z.object({ id: uuidSchema }).passthrough()).optional(),
      forced_skill: optionalStringSchema,
    })
    .strict(),
  session_live_status: z.object({ session_ids: z.array(uuidSchema) }).strict(),
  set_active_model: z
    .object({
      provider: z.string().min(1),
      model: z.string().min(1),
      trigger: activeModelSwitchTriggerSchema.optional(),
      reasoning_effort: z.string().optional(),
      thinking_mode: z.string().optional(),
    })
    .strict(),
  set_agent: z.object({ name: z.string().min(1) }).strict(),
  share_session: z.object({ session_id: uuidSchema, shared: z.boolean() }).strict(),
  stats_rollup: z
    .object({
      project_id: z.string().nullable().optional(),
      range: statsRangeSchema,
      by_role: z.boolean().optional(),
    })
    .strict(),
  unarchive_session: z.object({ session_id: uuidSchema }).strict(),
} as const;

type RequestParamSchemas = typeof requestParamSchemas;
type RequestVariant<Name extends keyof RequestParamSchemas> = {
  request: Name;
  params: z.infer<RequestParamSchemas[Name]>;
};

export type RequestName = keyof RequestParamSchemas;
export type ClientRequest = {
  [Name in RequestName]: RequestVariant<Name>;
}[RequestName];

function requestVariant<Name extends RequestName>(
  request: Name,
  params: RequestParamSchemas[Name],
) {
  return z.object({ request: z.literal(request), params }).strict();
}

export const clientRequestSchema: z.ZodType<ClientRequest> = z.discriminatedUnion("request", [
  requestVariant("archive_session", requestParamSchemas.archive_session),
  requestVariant("attach", requestParamSchemas.attach),
  requestVariant("cancel_paused_work", requestParamSchemas.cancel_paused_work),
  requestVariant("delete_session", requestParamSchemas.delete_session),
  requestVariant("fork_session", requestParamSchemas.fork_session),
  requestVariant("fs_create_dir", requestParamSchemas.fs_create_dir),
  requestVariant("fs_delete", requestParamSchemas.fs_delete),
  requestVariant("fs_list", requestParamSchemas.fs_list),
  requestVariant("fs_read", requestParamSchemas.fs_read),
  requestVariant("fs_rename", requestParamSchemas.fs_rename),
  requestVariant("fs_stat", requestParamSchemas.fs_stat),
  requestVariant("fs_write", requestParamSchemas.fs_write),
  requestVariant("git_diff_file", requestParamSchemas.git_diff_file),
  requestVariant("git_status", requestParamSchemas.git_status),
  requestVariant("list_sessions", requestParamSchemas.list_sessions),
  requestVariant("read_history_page", requestParamSchemas.read_history_page),
  requestVariant("read_session_messages", requestParamSchemas.read_session_messages),
  requestVariant("rename_session", requestParamSchemas.rename_session),
  requestVariant("resolve_interrupt", requestParamSchemas.resolve_interrupt),
  requestVariant("resume_paused_work", requestParamSchemas.resume_paused_work),
  requestVariant("send_user_message", requestParamSchemas.send_user_message),
  requestVariant("session_live_status", requestParamSchemas.session_live_status),
  requestVariant("set_active_model", requestParamSchemas.set_active_model),
  requestVariant("set_agent", requestParamSchemas.set_agent),
  requestVariant("share_session", requestParamSchemas.share_session),
  requestVariant("stats_rollup", requestParamSchemas.stats_rollup),
  requestVariant("unarchive_session", requestParamSchemas.unarchive_session),
]);

export const clientEnvelopeSchema = z.intersection(
  z
    .object({ v: z.literal(PROTOCOL_VERSION), kind: z.literal("req"), id: requestIdSchema })
    .strict(),
  clientRequestSchema,
);
export type ClientEnvelope = z.infer<typeof clientEnvelopeSchema>;

export const responseNameSchema = z.enum([
  "ack",
  "attached",
  "forked",
  "fs_list",
  "fs_read",
  "fs_stat",
  "fs_write",
  "git_diff_file",
  "git_status",
  "history_page",
  "models",
  "session_messages",
  "session_live_status",
  "sessions",
  "stats_rollup",
]);
export type ResponseName = z.infer<typeof responseNameSchema>;

const responseBaseSchema = {
  v: z.literal(PROTOCOL_VERSION),
  kind: z.literal("res"),
  id: requestIdSchema,
} as const;
export const sessionMessageSchema = z
  .object({
    seq: z.number().int(),
    ts_ms: z.number().int(),
    role: z.enum(["user", "agent"]),
    text: z.string(),
  })
  .passthrough();
export type SessionMessage = z.infer<typeof sessionMessageSchema>;

const interruptDecisionSchema = z
  .object({
    permission: z.boolean(),
    cancelled: z.boolean(),
    lines: z.array(z.object({ prompt: z.string(), answer: z.string() }).passthrough()),
  })
  .passthrough();

const historyEntryWireSchema = z.discriminatedUnion("role", [
  z
    .object({
      role: z.literal("interrupt_decision"),
      decision: interruptDecisionSchema,
      seq: z.number().int().optional(),
    })
    .passthrough(),
  z
    .object({
      role: z.literal("user"),
      text: z.string(),
      display_text: z.string().optional(),
      tag_expansions: z.array(passthroughObjectSchema).optional(),
      ts_ms: z.number().int().optional(),
      seq: z.number().int().optional(),
      origin_principal: z.string().optional(),
    })
    .passthrough(),
  z
    .object({
      role: z.literal("user_note"),
      text: z.string(),
      ts_ms: z.number().int().optional(),
      seq: z.number().int().optional(),
    })
    .passthrough(),
  z
    .object({
      role: z.literal("assistant"),
      agent: z.string(),
      text: z.string(),
      reasoning: z.string().optional(),
      ts_ms: z.number().int().optional(),
      seq: z.number().int().optional(),
    })
    .passthrough(),
  z
    .object({
      role: z.literal("tool_call"),
      seq: z.number().int().optional(),
      agent: z.string(),
      call_id: z.string(),
      parent_call_id: z.string().nullable().optional(),
      parent_child_index: z.number().int().nullable().optional(),
      tool: z.string(),
      mcp_server: z.string().nullable().optional(),
      mcp_builtin: z.boolean().nullable().optional(),
      mcp_kind: z.string().nullable().optional(),
      original_input: z.unknown(),
      wire_input: z.unknown(),
      recovery_kind: z.string().nullable().optional(),
      recovery_stage: z.string().nullable().optional(),
      output: z.string(),
      hard_fail: z.boolean(),
      truncated: z.boolean(),
      hint: z.string().optional(),
    })
    .passthrough(),
  z
    .object({
      role: z.literal("inference_error"),
      seq: z.number().int().optional(),
      summary: z.string(),
      detail: z.string().optional(),
    })
    .passthrough(),
  z
    .object({
      role: z.literal("compact_boundary"),
      seq: z.number().int().optional(),
      predecessor_short_id: z.string(),
      seed_tool_count: z.number().int().nonnegative(),
      seed_tool_tokens: z.number().int().nonnegative(),
      source: z.string().optional(),
      trigger_ctx_pct: z.number().nullable().optional(),
      tokens_before: z.number().int().nonnegative().optional(),
      tokens_after: z.number().int().nonnegative().optional(),
      turns_summarized: z.number().int().nonnegative().optional(),
      tail_kept: z.number().int().nonnegative().optional(),
      tail_trimmed: z.number().int().nonnegative().optional(),
      brief: z.string().optional(),
      handoff: z.string().optional(),
    })
    .passthrough(),
  z
    .object({
      role: z.literal("subagent"),
      seq: z.number().int().optional(),
      parent: z.string(),
      child: z.string(),
      task_call_id: z.string(),
      label: z.string(),
    })
    .passthrough(),
]);
const sessionSummaryWireSchema = z
  .object({
    session_id: uuidSchema,
    project_root: projectRootSchema,
    project_id: z.string(),
    started_at: z.number().int(),
    last_active_at: z.number().int(),
    turns: z.number().int().nonnegative(),
    active_agent: z.string(),
  })
  .passthrough();
const fsEntryWireSchema = z
  .object({
    name: z.string(),
    path: z.string(),
    kind: z.enum(["file", "directory", "symlink", "other"]),
    size: z.number().int().nonnegative(),
    gitignored: z.boolean(),
    blocked: z.boolean(),
  })
  .passthrough();
const liveStatusWireSchema = z
  .object({
    session_id: uuidSchema,
    has_active_schedules: z.boolean(),
    processing: z.boolean(),
  })
  .passthrough();
const statsRollupWireSchema = z
  .object({
    project_id: z.string().nullable(),
    range: z.string(),
    tokens: passthroughObjectSchema,
    recovery: passthroughObjectSchema,
    language: passthroughObjectSchema,
  })
  .passthrough();
const responseVariant = <Name extends ResponseName, Schema extends z.ZodTypeAny>(
  response: Name,
  data: Schema,
) => z.object({ ...responseBaseSchema, response: z.literal(response), data }).passthrough();

export const responseEnvelopeSchema = z.discriminatedUnion("response", [
  z.object({ ...responseBaseSchema, response: z.literal("ack") }).passthrough(),
  responseVariant(
    "attached",
    z
      .object({
        session_id: uuidSchema,
        short_id: z.string(),
        project_root: projectRootSchema,
        project_id: z.string(),
        active_agent: z.string(),
        history: z.array(historyEntryWireSchema),
      })
      .passthrough(),
  ),
  responseVariant(
    "sessions",
    z.object({ sessions: z.array(sessionSummaryWireSchema) }).passthrough(),
  ),
  responseVariant(
    "session_messages",
    z
      .object({
        session_id: uuidSchema,
        messages: z.array(sessionMessageSchema),
        has_more: z.boolean(),
      })
      .passthrough(),
  ),
  responseVariant(
    "history_page",
    z
      .object({
        session_id: uuidSchema,
        entries: z.array(historyEntryWireSchema),
        has_more: z.boolean(),
      })
      .passthrough(),
  ),
  responseVariant(
    "forked",
    z
      .object({
        session_id: uuidSchema,
        short_id: z.string(),
        parent_session_id: uuidSchema,
        fork_point_turn_id: z.string().nullable().optional(),
      })
      .passthrough(),
  ),
  responseVariant(
    "models",
    z
      .object({
        models: z.array(
          z
            .object({
              provider: z.string(),
              id: z.string(),
              display_name: z.string().nullable().optional(),
              favorite: z.boolean(),
            })
            .passthrough(),
        ),
      })
      .passthrough(),
  ),
  responseVariant("stats_rollup", z.object({ rollup: statsRollupWireSchema }).passthrough()),
  responseVariant(
    "fs_list",
    z.object({ entries: z.array(fsEntryWireSchema), truncated: z.boolean() }).passthrough(),
  ),
  responseVariant("fs_stat", z.object({ entry: fsEntryWireSchema }).passthrough()),
  responseVariant(
    "fs_read",
    z
      .object({
        content: z.string().nullable().optional(),
        hash: z.string().min(1),
        truncated: z.boolean(),
        kind: z.enum(["text", "binary", "image"]),
      })
      .passthrough(),
  ),
  responseVariant("fs_write", z.object({ hash: z.string().min(1) }).passthrough()),
  responseVariant(
    "git_status",
    z.object({ entries: z.array(z.object({ raw: z.string() }).passthrough()) }).passthrough(),
  ),
  responseVariant(
    "git_diff_file",
    z.object({ diff: z.string(), truncated: z.boolean() }).passthrough(),
  ),
  responseVariant(
    "session_live_status",
    z.object({ statuses: z.array(liveStatusWireSchema) }).passthrough(),
  ),
]);
export type ResponseEnvelope = z.infer<typeof responseEnvelopeSchema>;

export const errorPayloadSchema = z
  .object({
    code: z.string().min(1),
    message: z.string(),
  })
  .passthrough();
export const errorEnvelopeSchema = z
  .object({
    v: z.literal(PROTOCOL_VERSION),
    kind: z.literal("err"),
    id: requestIdSchema.optional(),
    error: errorPayloadSchema,
  })
  .passthrough();
export type ErrorEnvelope = z.infer<typeof errorEnvelopeSchema>;

export const knownEventKindSchema = z.enum([
  "active_model_state",
  "agent_idle",
  "approval_mode_state",
  "assistant_text",
  "assistant_text_delta",
  "backup_used",
  "caffeinate_state",
  "command_capability_unavailable",
  "compact_ready",
  "config_snapshot",
  "connector_status",
  "context_projection",
  "daemon_draining",
  "delegation_recursion_state",
  "env_drift_warning",
  "foreground_input_target",
  "gitignore_allow",
  "history_replay",
  "inference_failed",
  "inference_succeeded",
  "inference_warning",
  "interrupt_queue_changed",
  "interrupt_raised",
  "interrupt_resolved",
  "llm_mode_changed",
  "lsp_notice",
  "nested_turn",
  "notice",
  "paused_work_available",
  "preflight_started",
  "preflight_state",
  "primary_swapped",
  "pruned",
  "queue_updated",
  "queued_user_messages_folded",
  "reasoning_delta",
  "reconnecting",
  "redaction_state",
  "resource_clear",
  "resource_start",
  "resource_wait",
  "sandbox_escalation_state",
  "sandbox_state",
  "sandbox_unavailable",
  "schedule_completed",
  "schedule_note",
  "schedule_progress",
  "schedule_started",
  "session_driver_failed",
  "session_ended",
  "session_persist_failed",
  "skill_auto_injected",
  "subagent_report",
  "subagent_routing",
  "subagent_spawned",
  "tandem_state",
  "terminal_clipboard",
  "terminal_closed",
  "terminal_output",
  "terminal_viewers",
  "thinking_started",
  "tool_end",
  "tool_error",
  "tool_start",
  "trusted_only_state",
  "usage",
  "user_message_recorded",
  "user_message_retracted",
  "waiting_for_lock",
]);
export type KnownEventKind = z.infer<typeof knownEventKindSchema>;

const knownEventKinds = new Set<string>(knownEventKindSchema.options);
const interruptQuestionSetSchema = z
  .object({ questions: z.array(interruptQuestionSchema) })
  .passthrough();
const interruptRaisedDataSchema = z
  .object({
    session_id: uuidSchema,
    interrupt_id: uuidSchema,
    agent: z.string(),
    description: z.string(),
    question: interruptQuestionSchema.nullable().optional(),
    questions: interruptQuestionSetSchema.nullable().optional(),
    pending_count: z.number().int().nonnegative().optional(),
    reason: z.enum(["initial", "advance", "rehydration"]).optional(),
  })
  .passthrough();
const historyReplayDataSchema = z
  .object({
    session_id: uuidSchema,
    entries: z.array(historyEntryWireSchema),
    max_seq: z.number().int(),
  })
  .passthrough();
const interruptResolvedDataSchema = z
  .object({
    session_id: uuidSchema,
    interrupt_id: uuidSchema,
    decision: interruptDecisionSchema.optional(),
    seq: z.number().int().optional(),
  })
  .passthrough();
const structuredEventDataSchemas = {
  history_replay: historyReplayDataSchema,
  interrupt_raised: interruptRaisedDataSchema,
  interrupt_resolved: interruptResolvedDataSchema,
} as const satisfies Partial<Record<KnownEventKind, z.ZodTypeAny>>;

function validateKnownEventData(event: KnownEventKind, data: unknown, ctx: z.RefinementCtx) {
  const schema = structuredEventDataSchemas[event as keyof typeof structuredEventDataSchemas];
  if (!schema) return;
  const parsed = schema.safeParse(data);
  if (parsed.success) return;
  for (const issue of parsed.error.issues) {
    ctx.addIssue({ ...issue, path: ["data", ...issue.path] });
  }
}

export const knownEventEnvelopeSchema = z
  .object({
    v: z.literal(PROTOCOL_VERSION),
    kind: z.literal("evt"),
    event: knownEventKindSchema,
    data: z.unknown().optional(),
  })
  .passthrough()
  .superRefine((frame, ctx) => validateKnownEventData(frame.event, frame.data, ctx));
export type KnownEventEnvelope = z.infer<typeof knownEventEnvelopeSchema>;

export const eventEnvelopeSchema = z
  .object({
    v: z.literal(PROTOCOL_VERSION),
    kind: z.literal("evt"),
    event: z.string().min(1),
    data: z.unknown().optional(),
  })
  .passthrough()
  .superRefine((frame, ctx) => {
    if (knownEventKindSchema.safeParse(frame.event).success) {
      validateKnownEventData(frame.event as KnownEventKind, frame.data, ctx);
    }
  })
  .transform((frame) => {
    if (knownEventKinds.has(frame.event)) return frame;
    return {
      ...frame,
      __unknown: true as const,
    };
  });
export type EventEnvelope = z.infer<typeof eventEnvelopeSchema>;
export type UnknownEventEnvelope = EventEnvelope & { __unknown: true };

export const serverMessageSchema = z.union([
  responseEnvelopeSchema,
  eventEnvelopeSchema,
  errorEnvelopeSchema,
]);
export type ServerMessage = z.infer<typeof serverMessageSchema>;

export const historyEntrySchema = historyEntryWireSchema;
export type HistoryEntry = z.infer<typeof historyEntrySchema>;

export const sessionSummarySchema = z
  .object({
    session_id: uuidSchema,
    short_id: z.string().optional(),
    project_root: projectRootSchema,
    project_id: z.string(),
    started_at: z.number().int(),
    last_active_at: z.number().int(),
    turns: z.number().int().nonnegative(),
    active_agent: z.string(),
    title: z.string().nullable().optional(),
    parent_session_id: uuidSchema.nullable().optional(),
    created_by_principal: z.string().nullable().optional(),
    shared_with_collaborators: z.boolean().optional(),
  })
  .passthrough();
export type SessionSummary = z.infer<typeof sessionSummarySchema>;

export const fsEntryKindSchema = z.enum(["file", "directory", "symlink", "other"]);
export const fsReadKindSchema = z.enum(["text", "binary", "image"]);
export const fsEntrySchema = z
  .object({
    name: z.string(),
    path: z.string(),
    kind: fsEntryKindSchema,
    size: z.number().int().nonnegative(),
    mtime_ms: z.number().int().nullable().optional(),
    gitignored: z.boolean().optional(),
    blocked: z.boolean().optional(),
    symlink_target: z.string().nullable().optional(),
  })
  .passthrough();
export type FsEntry = z.infer<typeof fsEntrySchema>;

export const listSessionsResultSchema = z
  .object({ sessions: z.array(sessionSummarySchema) })
  .passthrough();
export const attachResultSchema = z
  .object({
    session_id: uuidSchema,
    short_id: z.string(),
    project_root: projectRootSchema,
    project_id: z.string(),
    active_agent: z.string(),
    history: z.array(historyEntrySchema),
  })
  .passthrough();
export const ackResultSchema = z.unknown();
export const sessionMessagesResultSchema = z
  .object({
    session_id: uuidSchema,
    messages: z.array(sessionMessageSchema),
    has_more: z.boolean(),
  })
  .passthrough();
export const historyPageResultSchema = z
  .object({ session_id: uuidSchema, entries: z.array(historyEntrySchema), has_more: z.boolean() })
  .passthrough();
export const fsListResultSchema = z
  .object({ entries: z.array(fsEntrySchema), truncated: z.boolean() })
  .passthrough();
export const fsStatResultSchema = z.object({ entry: fsEntrySchema }).passthrough();
export const fsReadResultSchema = z
  .object({
    content: z.string().nullable().optional(),
    hash: z.string().min(1),
    truncated: z.boolean(),
    kind: fsReadKindSchema,
  })
  .passthrough();
export const fsWriteResultSchema = z.object({ hash: z.string().min(1) }).passthrough();
export const gitStatusEntrySchema = z.object({ raw: z.string() }).passthrough();
export const gitStatusResultSchema = z
  .object({ entries: z.array(gitStatusEntrySchema) })
  .passthrough();
export const gitDiffFileResultSchema = z
  .object({ diff: z.string(), truncated: z.boolean() })
  .passthrough();
export const sessionLiveStatusResultSchema = z
  .object({ statuses: z.array(liveStatusWireSchema) })
  .passthrough();

export type AttachResult = z.infer<typeof attachResultSchema>;
export type AckResult = z.infer<typeof ackResultSchema>;
export type ListSessionsResult = z.infer<typeof listSessionsResultSchema>;
export type SessionMessagesResult = z.infer<typeof sessionMessagesResultSchema>;
export type HistoryPageResult = z.infer<typeof historyPageResultSchema>;
export type FsListResult = z.infer<typeof fsListResultSchema>;
export type FsStatResult = z.infer<typeof fsStatResultSchema>;
export type FsReadResult = z.infer<typeof fsReadResultSchema>;
export type FsWriteResult = z.infer<typeof fsWriteResultSchema>;
export type GitStatusResult = z.infer<typeof gitStatusResultSchema>;
export type GitDiffFileResult = z.infer<typeof gitDiffFileResultSchema>;
export type SessionLiveStatusResult = z.infer<typeof sessionLiveStatusResultSchema>;

export function parseListSessionsResult(value: unknown) {
  return listSessionsResultSchema.parse(value);
}
export function parseAttachResult(value: unknown) {
  return attachResultSchema.parse(value);
}
export function parseSessionMessagesResult(value: unknown) {
  return sessionMessagesResultSchema.parse(value);
}
export function parseHistoryPageResult(value: unknown) {
  return historyPageResultSchema.parse(value);
}
export function parseFsListResult(value: unknown) {
  return fsListResultSchema.parse(value);
}
export function parseFsStatResult(value: unknown) {
  return fsStatResultSchema.parse(value);
}
export function parseFsReadResult(value: unknown) {
  return fsReadResultSchema.parse(value);
}
export function parseFsWriteResult(value: unknown) {
  return fsWriteResultSchema.parse(value);
}
export function parseAckResult(value: unknown) {
  return ackResultSchema.parse(value);
}
export function parseGitStatusResult(value: unknown) {
  return gitStatusResultSchema.parse(value);
}
export function parseGitDiffFileResult(value: unknown) {
  return gitDiffFileResultSchema.parse(value);
}
export function parseSessionLiveStatusResult(value: unknown) {
  return sessionLiveStatusResultSchema.parse(value);
}

export function createEnvelope(id: string, request: ClientRequest): ClientEnvelope {
  return clientEnvelopeSchema.parse({ v: PROTOCOL_VERSION, kind: "req", id, ...request });
}
