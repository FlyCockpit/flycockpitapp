import { z } from "zod";

export const protocolVersionSchema = z.literal(1);
export const requestIdSchema = z.string().trim().min(1).max(128);
export const sessionIdSchema = z.string().trim().min(1).max(256);
export const projectRootSchema = z.string().trim().min(1).max(4096);

export const actorSchema = z
  .object({
    userId: z.string().min(1).optional(),
    displayName: z.string().min(1).optional(),
    origin: z.enum(["tui", "web", "native", "daemon", "schedule"]).optional(),
  })
  .passthrough();
export type CockpitActor = z.infer<typeof actorSchema>;

function actorFromPrincipal(principal: string | null | undefined): CockpitActor | null {
  if (!principal) return null;
  const [namespace, ...rest] = principal.split(":");
  const userId = rest.join(":").trim();
  if (namespace !== "flycockpit" || !userId) return null;
  return { userId };
}

export const sessionStatusSchema = z.enum(["idle", "running", "needs_attention", "archived"]);
export const attentionKindSchema = z.enum(["question", "approval", "error", "schedule"]);

export const sessionSummarySchema = z
  .object({
    sessionId: sessionIdSchema,
    projectRoot: projectRootSchema,
    title: z.string().min(1).max(240),
    shortId: z.string().min(1).max(24).optional(),
    status: sessionStatusSchema.default("idle"),
    archived: z.boolean().default(false),
    pinned: z.boolean().default(false),
    parentSessionId: sessionIdSchema.nullable().optional(),
    forkCount: z.number().int().nonnegative().default(0),
    turnCount: z.number().int().nonnegative().default(0),
    attention: z
      .object({ kind: attentionKindSchema, interruptId: z.string().min(1).optional() })
      .nullable()
      .optional(),
    updatedAt: z.number().int().nonnegative(),
    createdAt: z.number().int().nonnegative().optional(),
    createdBy: actorSchema.nullable().optional(),
    created_by_principal: z.string().nullable().optional(),
    sharedWithCollaborators: z.boolean().optional(),
    shared_with_collaborators: z.boolean().optional(),
    agent: z.string().min(1).optional(),
    model: z.string().min(1).optional(),
  })
  .passthrough()
  .transform(({ created_by_principal, shared_with_collaborators, ...summary }) => ({
    ...summary,
    createdBy: summary.createdBy ?? actorFromPrincipal(created_by_principal),
    sharedWithCollaborators: summary.sharedWithCollaborators ?? shared_with_collaborators ?? false,
  }));
export type SessionSummary = z.infer<typeof sessionSummarySchema>;

export const projectSummarySchema = z
  .object({
    projectId: z.string().trim().min(1).max(512),
    projectRoot: projectRootSchema,
    displayName: z.string().min(1).max(240),
    sessionCount: z.number().int().nonnegative(),
    archivedCount: z.number().int().nonnegative().default(0),
    lastActivityAt: z.number().int().nonnegative().nullable(),
    attentionCount: z.number().int().nonnegative().default(0),
  })
  .passthrough();
export type ProjectSummary = z.infer<typeof projectSummarySchema>;

export const interruptSchema = z
  .object({
    interruptId: z.string().min(1),
    kind: z.enum(["question", "approval"]),
    title: z.string().min(1).max(240),
    body: z.string().max(4000).optional(),
    choices: z.array(z.string().min(1).max(120)).optional(),
    resolved: z.boolean().default(false),
  })
  .passthrough();
export type CockpitInterrupt = z.infer<typeof interruptSchema>;

export const usageSchema = z
  .object({
    inputTokens: z.number().int().nonnegative().optional(),
    outputTokens: z.number().int().nonnegative().optional(),
    totalTokens: z.number().int().nonnegative().optional(),
  })
  .passthrough();
export type CockpitUsage = z.infer<typeof usageSchema>;

const baseHistoryEntry = z.object({
  id: z.string().min(1),
  seq: z.number().int().nonnegative(),
  ts: z.number().int().nonnegative(),
});

export const historyEntrySchema = z.discriminatedUnion("kind", [
  baseHistoryEntry
    .extend({
      kind: z.literal("user_message"),
      text: z.string(),
      actor: actorSchema.nullable().optional(),
      attachments: z
        .array(z.object({ name: z.string(), mimeType: z.string().optional() }).passthrough())
        .default([]),
    })
    .passthrough(),
  baseHistoryEntry.extend({ kind: z.literal("assistant_text"), text: z.string() }).passthrough(),
  baseHistoryEntry
    .extend({ kind: z.literal("assistant_reasoning"), text: z.string() })
    .passthrough(),
  baseHistoryEntry
    .extend({
      kind: z.literal("tool_call"),
      callId: z.string().min(1),
      name: z.string().min(1),
      status: z.enum(["running", "succeeded", "failed", "canceled"]).default("running"),
      userFacing: z.boolean().default(false),
      durationMs: z.number().int().nonnegative().optional(),
      input: z.unknown().optional(),
      output: z.unknown().optional(),
    })
    .passthrough(),
  baseHistoryEntry
    .extend({ kind: z.literal("inference_error"), message: z.string() })
    .passthrough(),
  baseHistoryEntry
    .extend({ kind: z.literal("boundary"), label: z.string().min(1).max(120) })
    .passthrough(),
  baseHistoryEntry
    .extend({ kind: z.literal("subagent_report"), title: z.string().min(1), body: z.string() })
    .passthrough(),
  baseHistoryEntry
    .extend({ kind: z.literal("interrupt"), interrupt: interruptSchema })
    .passthrough(),
]);
export type HistoryEntry = z.infer<typeof historyEntrySchema>;

export const liveEventSchema = z.discriminatedUnion("type", [
  z
    .object({
      type: z.literal("history_entry"),
      sessionId: sessionIdSchema,
      entry: historyEntrySchema,
    })
    .passthrough(),
  z
    .object({
      type: z.literal("assistant_delta"),
      sessionId: sessionIdSchema,
      seq: z.number().int().nonnegative(),
      entryId: z.string().min(1),
      delta: z.string(),
    })
    .passthrough(),
  z.object({ type: z.literal("session_updated"), summary: sessionSummarySchema }).passthrough(),
  z
    .object({
      type: z.literal("interrupt_resolved"),
      sessionId: sessionIdSchema,
      interruptId: z.string().min(1),
      seq: z.number().int().nonnegative().optional(),
    })
    .passthrough(),
  z
    .object({ type: z.literal("usage"), sessionId: sessionIdSchema, usage: usageSchema })
    .passthrough(),
  z.object({ type: z.literal("idle"), sessionId: sessionIdSchema }).passthrough(),
  z
    .object({
      type: z.literal("schedule_updated"),
      sessionId: sessionIdSchema,
      schedule: z.unknown(),
    })
    .passthrough(),
]);
export type LiveEvent = z.infer<typeof liveEventSchema>;

export const listProjectsResultSchema = z
  .object({ projects: z.array(projectSummarySchema) })
  .passthrough();
export const listSessionsResultSchema = z
  .object({ sessions: z.array(sessionSummarySchema) })
  .passthrough();
export const attachResultSchema = z
  .object({
    session: sessionSummarySchema,
    history: z.array(historyEntrySchema),
    nextSeq: z.number().int().nonnegative(),
    schedules: z.array(z.unknown()).default([]),
  })
  .passthrough();

export const fsEntryKindSchema = z.enum(["file", "directory", "symlink", "other"]);
export const fsReadKindSchema = z.enum(["text", "binary", "image"]);
export const fsEntrySchema = z
  .object({
    name: z.string(),
    path: z.string(),
    kind: fsEntryKindSchema,
    size: z.number().int().nonnegative(),
    mtimeMs: z.number().int().nullable().optional(),
    mtime_ms: z.number().int().nullable().optional(),
    gitignored: z.boolean().default(false),
    blocked: z.boolean().default(false),
    symlinkTarget: z.string().nullable().optional(),
    symlink_target: z.string().nullable().optional(),
  })
  .transform((entry) => ({
    name: entry.name,
    path: entry.path,
    kind: entry.kind,
    size: entry.size,
    mtimeMs: entry.mtimeMs ?? entry.mtime_ms ?? null,
    gitignored: entry.gitignored,
    blocked: entry.blocked,
    symlinkTarget: entry.symlinkTarget ?? entry.symlink_target ?? null,
  }));
export type FsEntry = z.infer<typeof fsEntrySchema>;

export const fsListResultSchema = z
  .object({ entries: z.array(fsEntrySchema), truncated: z.boolean().default(false) })
  .passthrough();
export const fsReadResultSchema = z
  .object({
    content: z.string().nullable().optional(),
    hash: z.string().min(1),
    truncated: z.boolean().default(false),
    kind: fsReadKindSchema,
  })
  .passthrough();
export const fsWriteResultSchema = z.object({ hash: z.string().min(1) }).passthrough();
export const ackResultSchema = z.union([z.object({}).passthrough(), z.null(), z.undefined()]);
export const gitStatusEntrySchema = z.object({ raw: z.string() }).passthrough();
export const gitStatusResultSchema = z
  .object({ entries: z.array(gitStatusEntrySchema) })
  .passthrough();
export const gitDiffFileResultSchema = z
  .object({ diff: z.string(), truncated: z.boolean().default(false) })
  .passthrough();

export type FsListResult = z.infer<typeof fsListResultSchema>;
export type FsReadResult = z.infer<typeof fsReadResultSchema>;
export type FsWriteResult = z.infer<typeof fsWriteResultSchema>;
export type AckResult = z.infer<typeof ackResultSchema>;
export type GitStatusResult = z.infer<typeof gitStatusResultSchema>;
export type GitDiffFileResult = z.infer<typeof gitDiffFileResultSchema>;

export const clientRequestSchema = z.discriminatedUnion("type", [
  z.object({ type: z.literal("list_projects") }).strict(),
  z.object({ type: z.literal("list_sessions"), projectRoot: projectRootSchema }).strict(),
  z
    .object({
      type: z.literal("attach"),
      sessionId: sessionIdSchema,
      sinceSeq: z.number().int().nonnegative().optional(),
    })
    .strict(),
  z
    .object({
      type: z.literal("create_session"),
      projectRoot: projectRootSchema,
      title: z.string().min(1).max(240).optional(),
      agent: z.string().min(1).optional(),
      model: z.string().min(1).optional(),
    })
    .strict(),
  z
    .object({
      type: z.literal("send_user_message"),
      sessionId: sessionIdSchema,
      text: z.string().min(1),
      clientMessageId: z.string().min(1),
    })
    .strict(),
  z
    .object({
      type: z.literal("resolve_interrupt"),
      sessionId: sessionIdSchema,
      interruptId: z.string().min(1),
      resolution: z.enum(["approve", "deny", "answer"]),
      answer: z.string().optional(),
    })
    .strict(),
  z
    .object({ type: z.literal("set_model"), sessionId: sessionIdSchema, model: z.string().min(1) })
    .strict(),
  z
    .object({ type: z.literal("set_agent"), sessionId: sessionIdSchema, agent: z.string().min(1) })
    .strict(),
  z
    .object({
      type: z.literal("rename_session"),
      sessionId: sessionIdSchema,
      title: z.string().min(1).max(240),
    })
    .strict(),
  z.object({ type: z.literal("fork_session"), sessionId: sessionIdSchema }).strict(),
  z
    .object({ type: z.literal("share_session"), sessionId: sessionIdSchema, shared: z.boolean() })
    .strict(),
  z
    .object({
      type: z.literal("archive_session"),
      sessionId: sessionIdSchema,
      archived: z.boolean(),
    })
    .strict(),
  z
    .object({
      type: z.literal("cancel_schedule"),
      sessionId: sessionIdSchema,
      scheduleId: z.string().min(1),
    })
    .strict(),
  z
    .object({
      type: z.literal("fs_list"),
      projectRoot: projectRootSchema,
      path: z.string(),
      showHidden: z.boolean().default(false),
    })
    .strict(),
  z
    .object({ type: z.literal("fs_read"), projectRoot: projectRootSchema, path: z.string() })
    .strict(),
  z
    .object({
      type: z.literal("fs_write"),
      projectRoot: projectRootSchema,
      path: z.string(),
      content: z.string(),
      baseHash: z.string().optional(),
    })
    .strict(),
  z
    .object({ type: z.literal("fs_create_dir"), projectRoot: projectRootSchema, path: z.string() })
    .strict(),
  z
    .object({
      type: z.literal("fs_rename"),
      projectRoot: projectRootSchema,
      fromPath: z.string(),
      toPath: z.string(),
    })
    .strict(),
  z
    .object({ type: z.literal("fs_delete"), projectRoot: projectRootSchema, path: z.string() })
    .strict(),
  z.object({ type: z.literal("git_status"), projectRoot: projectRootSchema }).strict(),
  z
    .object({ type: z.literal("git_diff_file"), projectRoot: projectRootSchema, path: z.string() })
    .strict(),
]);
export type ClientRequest = z.infer<typeof clientRequestSchema>;

export const clientEnvelopeSchema = z
  .object({ id: requestIdSchema, request: clientRequestSchema })
  .strict();
export type ClientEnvelope = z.infer<typeof clientEnvelopeSchema>;

export const serverMessageSchema = z.union([
  z
    .object({
      type: z.literal("response"),
      id: requestIdSchema,
      ok: z.literal(true),
      result: z.unknown(),
    })
    .passthrough(),
  z
    .object({
      type: z.literal("response"),
      id: requestIdSchema,
      ok: z.literal(false),
      error: z.object({ code: z.string().min(1), message: z.string().min(1) }).passthrough(),
    })
    .passthrough(),
  z.object({ type: z.literal("event"), event: liveEventSchema }).passthrough(),
]);
export type ServerMessage = z.infer<typeof serverMessageSchema>;

export type AttachResult = z.infer<typeof attachResultSchema>;

export function parseListProjectsResult(value: unknown) {
  return listProjectsResultSchema.parse(value);
}
export function parseListSessionsResult(value: unknown) {
  return listSessionsResultSchema.parse(value);
}
export function parseAttachResult(value: unknown) {
  return attachResultSchema.parse(value);
}
export function parseFsListResult(value: unknown) {
  return fsListResultSchema.parse(value);
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
export function createEnvelope(id: string, request: ClientRequest): ClientEnvelope {
  return clientEnvelopeSchema.parse({ id, request });
}
