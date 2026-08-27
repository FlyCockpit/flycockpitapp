import { z } from "zod";
import { canonicalU64DecimalStringSchema, decodeProtocolIdBase64Url } from "./remote-protocol-id";

export * from "./dependency-health";
export * from "./remote-attempt-grants";
export * from "./remote-connection-metadata";
export * from "./remote-device-identity-enrollment";
export * from "./remote-identity-custody-provider";
export * from "./remote-identity-protocol";
export * from "./remote-noise-binding";
export * from "./remote-public-service-policy";
export * from "./remote-tenant-authority-protocol";
export * from "./remote-transport-selection";
export * from "./remote-websocket-fallback";
export * from "./remote-wire-magic-registry";
export * from "./send-user-message-v2";

export const PROTOCOL_VERSION = 21 as const;

/** Immutable daemon-owned session setup metadata; never an authority grant. */
export const sessionEntryModeSchema = z.enum(["code", "assistant", "computer"]);
export type SessionEntryMode = z.infer<typeof sessionEntryModeSchema>;

/**
 * JSON form of a bulk transfer reference, mirroring Rust
 * `RemoteBulkTransferRef`. Application messages carry this instead of inline
 * bytes; the bytes themselves travel as bulk-lane chunks.
 */
/**
 * A 22-character opaque id, validated by the landed codec rather than by shape.
 *
 * A regex alone accepts spellings Rust rejects — notably the all-zero id
 * `"AAAAAAAAAAAAAAAAAAAAAA"` and non-canonical trailing bits — so the wire
 * schema must run the same decoder the binary path does.
 */
const opaqueProtocolIdSchema = z.string().superRefine((value, ctx) => {
  try {
    decodeProtocolIdBase64Url(value);
  } catch (error) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: error instanceof Error ? error.message : "invalid protocol id",
    });
  }
});

/** A `u32` wire field: Rust bounds this by type, so the schema must too. */
const u32Schema = z.number().int().nonnegative().max(0xffffffff);
/** JSON-number projection of Rust `u64`; unsafe integers cannot round-trip exactly in JS. */
const safeU64NumberSchema = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
/** JSON-number projection of Rust `i64`; unsafe integers cannot round-trip exactly in JS. */
const safeI64NumberSchema = z
  .number()
  .int()
  .min(Number.MIN_SAFE_INTEGER)
  .max(Number.MAX_SAFE_INTEGER);
const positiveSafeU64NumberSchema = z.number().int().positive().max(Number.MAX_SAFE_INTEGER);

export const bulkTransferRefSchema = z
  .object({
    /** 22-character unpadded base64url, via the landed identifier codec. */
    transfer_id: opaqueProtocolIdSchema,
    /** CanonicalU64DecimalStringV1 — never a JSON number. */
    total_length: canonicalU64DecimalStringSchema,
    /** Lowercase hex SHA-256 of the transferred bytes. */
    sha256: z
      .string()
      .length(64)
      .regex(/^[0-9a-f]{64}$/),
    mime_class: z.enum(["image", "image_set", "archive", "export", "opaque", "redacted_export"]),
  })
  .strict();
export type BulkTransferRef = z.infer<typeof bulkTransferRefSchema>;

/** Export metadata plus a bounded reference to the exported bytes. */
export const exportSessionDataSchema = z
  .object({
    session_id: z.string().uuid(),
    kind: z.enum(["transcript_json", "debug_bundle"]),
    filename_extension: z.string(),
    mime: z.string(),
    transfer: bulkTransferRefSchema,
    session_count: z.number().int().nonnegative().optional(),
    redacted: z.boolean(),
  })
  .passthrough();

export const uuidSchema = z.string().uuid();
// Rust rejects nil identifiers on every agent-tree request boundary. Keep the
// general UUID schema permissive for legacy wire shapes that intentionally use
// nil as a sentinel, and opt the lifecycle contracts into this exact rule.
const nonNilUuidSchema = uuidSchema.refine(
  (value) => value !== "00000000-0000-0000-0000-000000000000",
  "expected a nonnil UUID",
);
const canonicalRfcUuidSchema = uuidSchema.refine(
  (value) =>
    value === value.toLowerCase() &&
    value !== "00000000-0000-0000-0000-000000000000" &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value),
  "expected a canonical lowercase nonnil RFC UUID",
);
const uuidV7Schema = canonicalRfcUuidSchema.refine(
  (value) => value[14] === "7",
  "expected a UUIDv7 operation identity",
);
export const remoteOperationIdentityV1Schema = z
  .object({
    schemaVersion: z.literal(1),
    logicalAttachmentId: canonicalRfcUuidSchema,
    operationId: uuidV7Schema,
  })
  .strict();
export type RemoteOperationIdentityV1 = z.infer<typeof remoteOperationIdentityV1Schema>;
export const remoteReplayRequestV2Schema = z
  .object({
    v: z.literal(PROTOCOL_VERSION),
    kind: z.literal("replay_req"),
    id: canonicalRfcUuidSchema,
    afterEventSeq: canonicalU64DecimalStringSchema.optional(),
    limit: z.number().int().min(1).max(256),
  })
  .strict();
export const remoteOutboxDeliveryV1Schema = z
  .object({
    eventSeq: canonicalU64DecimalStringSchema,
    deliveryId: canonicalRfcUuidSchema,
    kind: z.string().min(1).max(255),
    canonicalPayload: z.array(z.number().int().min(0).max(255)).max(524288),
    leaseToken: canonicalRfcUuidSchema,
    leaseExpiresAtMs: safeI64NumberSchema,
  })
  .strict();
export const remoteReplayResponseV2Schema = z
  .object({
    v: z.literal(PROTOCOL_VERSION),
    kind: z.literal("replay_res"),
    id: canonicalRfcUuidSchema,
    events: z.array(remoteOutboxDeliveryV1Schema).max(256),
    highWaterMark: canonicalU64DecimalStringSchema,
  })
  .strict();
export const remoteReplayAckV2Schema = z
  .object({
    v: z.literal(PROTOCOL_VERSION),
    kind: z.literal("replay_ack"),
    id: canonicalRfcUuidSchema,
    deliveryId: canonicalRfcUuidSchema,
    leaseToken: canonicalRfcUuidSchema,
  })
  .strict();
export const remoteReplayAckResponseV2Schema = z
  .object({
    v: z.literal(PROTOCOL_VERSION),
    kind: z.literal("replay_ack_res"),
    id: canonicalRfcUuidSchema,
    acked: z.boolean(),
  })
  .strict();
const clientSubmissionIdSchema = uuidSchema.refine(
  (value) => value !== "00000000-0000-0000-0000-000000000000",
  { message: "client_submission_id must not be nil" },
);
export function createClientSubmissionId() {
  return globalThis.crypto.randomUUID();
}

/**
 * Largest 48-bit Unix-millisecond timestamp representable in an RFC 9562
 * UUIDv7 (2^48 - 1). Timestamps outside `[0, MAX_UUID_V7_UNIX_MS]` cannot be
 * encoded and are rejected.
 */
export const MAX_UUID_V7_UNIX_MS = 0xffff_ffff_ffff;

export interface GenerateRemoteOperationUuidV7Options {
  /** Wall-clock time in Unix milliseconds. Integer in `[0, MAX_UUID_V7_UNIX_MS]`. */
  nowMs: number;
  /**
   * CSPRNG fill, e.g. `(bytes) => crypto.getRandomValues(bytes)`. The buffer is
   * always a fresh `ArrayBuffer`-backed `Uint8Array` (typed as such so it
   * satisfies `crypto.getRandomValues`, which rejects a generic `ArrayBufferLike`).
   */
  getRandomValues: (bytes: Uint8Array<ArrayBuffer>) => void;
  /**
   * Already-issued identities. A collision re-rolls the random bits before the
   * first submission. This provides no cross-process monotonic ordering.
   */
  seen?: { has(id: string): boolean };
  /** Maximum re-rolls on collision before failing closed. Defaults to 8. */
  maxAttempts?: number;
}

/**
 * Pure RFC 9562 UUIDv7 operation-identity generator over an injected wall clock
 * and CSPRNG. The 48-bit big-endian `nowMs` fills bytes 0-5, version `7` goes in
 * the high nibble of byte 6, the RFC 4122 variant (`0b10`) in the top two bits
 * of byte 8, and every remaining bit comes from `getRandomValues`. Rust builds
 * the same layout; the shared vectors in
 * `fixtures/remote-operation-uuidv7-v1.json` lock byte-identity across languages.
 */
export function generateRemoteOperationUuidV7(
  options: GenerateRemoteOperationUuidV7Options,
): string {
  const { nowMs, getRandomValues, seen, maxAttempts = 8 } = options;
  if (!Number.isInteger(nowMs) || nowMs < 0 || nowMs > MAX_UUID_V7_UNIX_MS) {
    throw new RangeError(
      `UUIDv7 timestamp must be an integer in [0, ${MAX_UUID_V7_UNIX_MS}], got ${nowMs}`,
    );
  }
  // Bound the collision retry so the cap is genuinely fail-closed: a non-finite
  // `maxAttempts` (e.g. Infinity) with an always-colliding `seen` would otherwise
  // loop forever instead of throwing.
  if (!Number.isInteger(maxAttempts) || maxAttempts < 1) {
    throw new RangeError(`UUIDv7 maxAttempts must be a positive integer, got ${maxAttempts}`);
  }
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const bytes = new Uint8Array(16);
    getRandomValues(bytes);
    // 48-bit big-endian Unix millisecond timestamp. Division avoids the 32-bit
    // truncation of the bitwise operators for the high-order bytes.
    bytes[0] = Math.floor(nowMs / 2 ** 40) & 0xff;
    bytes[1] = Math.floor(nowMs / 2 ** 32) & 0xff;
    bytes[2] = Math.floor(nowMs / 2 ** 24) & 0xff;
    bytes[3] = Math.floor(nowMs / 2 ** 16) & 0xff;
    bytes[4] = Math.floor(nowMs / 2 ** 8) & 0xff;
    bytes[5] = nowMs & 0xff;
    // Version 7 in the high nibble of byte 6; keep the four random low bits.
    bytes[6] = 0x70 | (bytes[6]! & 0x0f);
    // RFC 4122 variant (0b10) in the top two bits of byte 8; keep six random bits.
    bytes[8] = 0x80 | (bytes[8]! & 0x3f);
    const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
    const id = `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
    if (!seen?.has(id)) {
      return id;
    }
  }
  throw new Error("could not generate a collision-free UUIDv7 operation identity");
}
export const requestIdSchema = uuidSchema;
export const thinkingModeSchema = z.enum(["off", "low", "medium", "high"]);
export type ThinkingMode = z.infer<typeof thinkingModeSchema>;
export const promptCacheRetentionSchema = z.enum(["default", "extended"]);
export type PromptCacheRetention = z.infer<typeof promptCacheRetentionSchema>;

// ---------------------------------------------------------------------------
// Typed media tool-result transport — canonical schema
// ---------------------------------------------------------------------------

/**
 * Canonical media kind, mirroring Rust `CanonicalMediaKind`.
 */
export const canonicalMediaKindSchema = z.enum(["image", "audio", "video"]);
export type CanonicalMediaKind = z.infer<typeof canonicalMediaKindSchema>;

/**
 * Availability snapshot at recording time, mirroring Rust
 * `MediaReferenceAvailability`.
 */
export const mediaReferenceAvailabilitySchema = z.enum(["ready", "processing", "unavailable"]);
export type MediaReferenceAvailability = z.infer<typeof mediaReferenceAvailabilitySchema>;

/**
 * Purpose of a media reference, mirroring Rust `MediaReferencePurpose`.
 */
export const mediaReferencePurposeSchema = z.enum(["primary", "sidecar", "contextual"]);
export type MediaReferencePurpose = z.infer<typeof mediaReferencePurposeSchema>;

/**
 * Known image dimensions, mirroring Rust `MediaDimensions`.
 */
export const mediaDimensionsSchema = z
  .object({
    width: z.number().int().nonnegative(),
    height: z.number().int().nonnegative(),
  })
  .strict();
export type MediaDimensions = z.infer<typeof mediaDimensionsSchema>;

/**
 * Known media duration in milliseconds, mirroring Rust `MediaDurationMs`.
 */
export const mediaDurationMsSchema = z
  .object({
    durationMs: z.number().int().nonnegative(),
  })
  .strict();
export type MediaDurationMs = z.infer<typeof mediaDurationMsSchema>;

/**
 * Sanitized provenance metadata, mirroring Rust `MediaProvenance`.
 * Contains no raw paths, URLs, or credentials.
 */
export const mediaProvenanceSchema = z
  .object({
    toolName: z.string().min(1).max(256),
    sourceLabel: z.string().min(1).max(1024).optional(),
  })
  .strict();
export type MediaProvenance = z.infer<typeof mediaProvenanceSchema>;

/**
 * An opaque reference to a retained media attachment, mirroring Rust
 * `MediaReference`. Contains no bytes, paths, provider URLs, or data URLs.
 */
export const mediaReferenceSchema = z
  .object({
    attachmentId: uuidSchema,
    attachmentVersion: z.number().int().positive(),
    mediaKind: canonicalMediaKindSchema,
    mimeType: z.string().min(1).max(256),
    ordinal: z.number().int().nonnegative(),
    purpose: mediaReferencePurposeSchema,
    checksum: z.string().regex(/^[0-9a-f]{64}$/),
    byteCount: z.number().int().nonnegative(),
    dimensions: mediaDimensionsSchema.optional(),
    durationMs: mediaDurationMsSchema.optional(),
    availability: mediaReferenceAvailabilitySchema,
    provenance: mediaProvenanceSchema,
  })
  .strict();
export type MediaReference = z.infer<typeof mediaReferenceSchema>;

/**
 * The one canonical media-bearing tool-result content union, mirroring Rust
 * `CanonicalToolResultContent`. Persist/daemon/protocol always carry this
 * union and never bytes/paths/provider URLs.
 */
export const canonicalToolResultContentSchema = z.discriminatedUnion("kind", [
  z
    .object({
      kind: z.literal("text"),
      text: z.string(),
    })
    .strict(),
  z
    .object({
      kind: z.literal("json"),
      value: z.unknown(),
    })
    .strict(),
  z
    .object({
      kind: z.literal("media_reference"),
      attachmentId: uuidSchema,
      attachmentVersion: z.number().int().positive(),
      mediaKind: canonicalMediaKindSchema,
      mimeType: z.string().min(1).max(256),
      ordinal: z.number().int().nonnegative(),
      purpose: mediaReferencePurposeSchema,
      checksum: z.string().regex(/^[0-9a-f]{64}$/),
      byteCount: z.number().int().nonnegative(),
      dimensions: mediaDimensionsSchema.optional(),
      durationMs: mediaDurationMsSchema.optional(),
      availability: mediaReferenceAvailabilitySchema,
      provenance: mediaProvenanceSchema,
    })
    .strict(),
]);
export type CanonicalToolResultContent = z.infer<typeof canonicalToolResultContentSchema>;

/**
 * Safe media metadata for client rendering, mirroring Rust `SafeMediaMetadata`.
 * Web/native/TUI render this without eager byte fetch or path assumptions.
 */
export const safeMediaMetadataSchema = z
  .object({
    attachmentId: uuidSchema,
    mediaKind: canonicalMediaKindSchema,
    mimeType: z.string().min(1).max(256),
    byteCount: z.number().int().nonnegative(),
    ordinal: z.number().int().nonnegative(),
    purpose: mediaReferencePurposeSchema,
    dimensions: mediaDimensionsSchema.optional(),
    durationMs: mediaDurationMsSchema.optional(),
    provenance: mediaProvenanceSchema,
    artifactHandle: z.string().optional(),
  })
  .strict();
export type SafeMediaMetadata = z.infer<typeof safeMediaMetadataSchema>;

export const activeModelRefSchema = z
  .object({
    provider: z.string().min(1),
    model: z.string().min(1),
    reasoning_effort: z.object({ value: z.string().min(1) }).optional(),
    thinking_mode: thinkingModeSchema.optional(),
    prompt_cache_retention: promptCacheRetentionSchema.optional(),
  })
  .passthrough();
export type ActiveModelRef = z.infer<typeof activeModelRefSchema>;

export const activeModelStateSchema = z
  .object({
    selection: activeModelRefSchema,
    default_selection: activeModelRefSchema.nullable().optional(),
    diverged: z.boolean(),
    // Monotonic only inside one attachment/worker epoch. An attach snapshot
    // is authoritative generation zero, so clients reset before merging it.
    generation: safeU64NumberSchema,
  })
  .passthrough();
export type ActiveModelState = z.infer<typeof activeModelStateSchema>;
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
        data: z.object({ selected_ids: z.array(z.string().min(1)).min(1) }).passthrough(),
      })
      .passthrough(),
    z
      .object({
        kind: z.literal("freetext"),
        data: z.object({ text: z.string().min(1) }).passthrough(),
      })
      .passthrough(),
    z
      .object({
        kind: z.literal("batch"),
        data: z.object({ responses: z.array(resolveResponseSchema).min(1) }).passthrough(),
      })
      .passthrough(),
    z.object({ kind: z.literal("cancel") }).passthrough(),
  ]),
);
export type ResolveResponse = z.infer<typeof resolveResponseSchema>;

/** Stable opaque position for daemon-owned agent tree and Attention pages. */
export const agentTreeCursorSchema = z
  .object({ created_at_unix_ms: safeI64NumberSchema, id: nonNilUuidSchema })
  .strict();
export type AgentTreeCursor = z.infer<typeof agentTreeCursorSchema>;

/** Resolver-context-free lifecycle projection owned by the daemon. */
export const agentTreeNodeSchema = z
  .object({
    agent_instance_id: nonNilUuidSchema,
    parent_agent_instance_id: nonNilUuidSchema.nullable().optional(),
    workspace_ref: z.string().nullable().optional(),
    state: z.string().min(1),
    revision: safeI64NumberSchema,
    created_at_unix_ms: safeI64NumberSchema,
    updated_at_unix_ms: safeI64NumberSchema,
  })
  .strict();
export type AgentTreeNode = z.infer<typeof agentTreeNodeSchema>;

/** Allowlisted decision Attention projection. Resolver prompts and receipts are excluded. */
export const agentDecisionAttentionSchema = z
  .object({
    attention_id: nonNilUuidSchema,
    decision_request_id: nonNilUuidSchema,
    agent_instance_id: nonNilUuidSchema,
    state: z.string().min(1),
    decision_state: z.string().min(1),
    decision_class: z.string().min(1),
    task_call_id: z.string().min(1).nullable().optional(),
    workspace_ref: z.string().min(1).nullable().optional(),
    options_contract_json: z.string(),
    free_text_contract_json: z.string().nullable().optional(),
    recommendation_json: z.string().nullable().optional(),
    deadline_unix_ms: safeI64NumberSchema.nullable().optional(),
    revision: safeI64NumberSchema,
    raised_at_unix_ms: safeI64NumberSchema,
    resolved_at_unix_ms: safeI64NumberSchema.nullable().optional(),
  })
  .strict();
export type AgentDecisionAttention = z.infer<typeof agentDecisionAttentionSchema>;

export const agentDecisionAnswerSchema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("option"), option_id: z.string().min(1) }).strict(),
  z.object({ kind: z.literal("free_text"), text: z.string().min(1) }).strict(),
  z
    .object({
      kind: z.literal("interrupt_response"),
      response: resolveResponseSchema,
    })
    .strict(),
]);
export type AgentDecisionAnswer = z.infer<typeof agentDecisionAnswerSchema>;

const requestParamSchemas = {
  get_app_flag: z.object({ key: z.literal("daemon_autostart_notice") }).strict(),
  get_startup_disclosures: z.object({ project_root: projectRootSchema }).strict(),
  mark_app_flag_seen: z
    .object({
      key: z.literal("daemon_autostart_notice"),
      expected_version: safeU64NumberSchema,
    })
    .strict(),
  resolve_assistant_session: z
    .object({
      assistant_id: z.string().min(1),
      project_root: projectRootSchema,
      mode: z.literal("most_recent_or_create"),
    })
    .strict(),
  set_workspace_trust: z
    .object({
      project_root: projectRootSchema,
      mode: z.enum(["trust", "ignore_config", "untrusted"]),
      expected_config_generation: safeU64NumberSchema,
    })
    .strict(),
  archive_session: z.object({ session_id: uuidSchema, cascade: z.boolean().optional() }).strict(),
  attach: z.union([
    // A fresh session has no durable session identity yet, so it must name
    // its non-authoritative entry presentation explicitly.
    z
      .object({
        session_id: z.undefined().optional(),
        since_seq: safeI64NumberSchema.optional(),
        project_root: projectRootSchema,
        no_sandbox: z.boolean().optional(),
        interactive: z.boolean().optional(),
        session_entry_mode: sessionEntryModeSchema,
        initial_model: activeModelRefSchema.optional(),
        model_override: activeModelRefSchema.optional(),
        client_protocol_version: z.number().int().nonnegative().optional(),
        env_snapshot: z.unknown().optional(),
        env_policy: envDriftPolicySchema.optional(),
      })
      .strict(),
    // A resume is keyed by durable session identity. The daemon reloads the
    // mode; a caller may only provide an exact value for explicit checking.
    z
      .object({
        session_id: uuidSchema,
        since_seq: safeI64NumberSchema.optional(),
        project_root: z.string().optional(),
        no_sandbox: z.boolean().optional(),
        interactive: z.boolean().optional(),
        session_entry_mode: sessionEntryModeSchema.optional(),
        initial_model: activeModelRefSchema.optional(),
        model_override: activeModelRefSchema.optional(),
        client_protocol_version: z.number().int().nonnegative().optional(),
        env_snapshot: z.unknown().optional(),
        env_policy: envDriftPolicySchema.optional(),
      })
      .strict(),
  ]),
  cancel_paused_work: z.object({ session_id: uuidSchema }).strict(),
  delete_session: z.object({ session_id: uuidSchema }).strict(),
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
  get_inventory_bundle: z
    .object({
      session_id: uuidSchema,
      project_root: projectRootSchema,
      selected_agent: z.string().min(1),
    })
    .strict(),
  get_session_setup_snapshot: z.object({ session_id: uuidSchema }).strict(),
  list_sessions: z
    .object({
      project_id: z.string().nullable().optional(),
      parent_session_id: optionalUuidSchema,
      assistant_id: z.string().nullable().optional(),
    })
    .strict(),
  read_history_page: z
    .object({
      session_id: uuidSchema,
      before_seq: safeI64NumberSchema.nullable().optional(),
      limit: z.number().int().positive(),
    })
    .strict(),
  read_subagent_history_page: z
    .object({
      session_id: uuidSchema,
      task_call_id: z.string().min(1),
      label: z.string().min(1),
      before_seq: safeI64NumberSchema.nullable().optional(),
      limit: z.number().int().positive(),
    })
    .strict(),
  read_agent_tree: z
    .object({
      session_id: nonNilUuidSchema,
      root_agent_instance_id: nonNilUuidSchema.nullable().optional(),
      after: agentTreeCursorSchema.nullable().optional(),
      limit: z.number().int().min(1).max(100),
    })
    .strict(),
  read_agent_attention: z
    .object({
      session_id: nonNilUuidSchema,
      after: agentTreeCursorSchema.nullable().optional(),
      limit: z.number().int().min(1).max(100),
    })
    .strict(),
  resolve_agent_decision: z
    .object({
      session_id: nonNilUuidSchema,
      decision_request_id: nonNilUuidSchema,
      answer: agentDecisionAnswerSchema,
    })
    .strict(),
  read_session_messages: z
    .object({
      session_id: uuidSchema,
      before_seq: safeI64NumberSchema.nullable().optional(),
      limit: z.number().int().positive(),
    })
    .strict(),
  rename_session: z.object({ session_id: uuidSchema, title: z.string().min(1).max(240) }).strict(),
  resolve_interrupt: z
    .object({ interrupt_id: uuidSchema, response: resolveResponseSchema })
    .strict(),
  restart_if_idle: z.undefined(),
  resume_paused_work: z.object({ session_id: uuidSchema }).strict(),
  send_user_message: z
    .object({
      client_submission_id: clientSubmissionIdSchema,
      // Authenticated clients can author only root user activity. Internal
      // provenance is assigned by the daemon at the owning dispatch site.
      origin: z.literal("external_root"),
      expected_model_state_generation: safeU64NumberSchema.optional(),
      expected_model: activeModelRefSchema.optional(),
      text: z.string(),
      display_text: optionalStringSchema,
      tag_expansions: z.array(passthroughObjectSchema).optional(),
      image_refs: z.array(z.object({ id: uuidSchema }).passthrough()).optional(),
      forced_skill: optionalStringSchema,
      run_invocation_options: z
        .object({
          max_turns: z.number().int().positive().optional(),
          timeout_ms: positiveSafeU64NumberSchema.optional(),
          approval_mode: z.enum(["manual", "auto", "yolo"]).optional(),
        })
        .strict()
        .optional(),
    })
    .strict()
    .superRefine((value, ctx) => {
      if (
        (value.expected_model_state_generation === undefined) !==
        (value.expected_model === undefined)
      ) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "expected model generation and identity must be supplied together",
        });
      }
    }),
  // The body is UTF-8 bytes staged through the existing bulk lane. Keeping
  // this request reference-only prevents a 64KiB..8MiB user message from ever
  // crossing the 524360-byte application-frame cap.
  send_user_message_bulk: z
    .object({
      client_submission_id: clientSubmissionIdSchema,
      origin: z.literal("external_root"),
      expected_model_state_generation: safeU64NumberSchema.optional(),
      expected_model: activeModelRefSchema.optional(),
      transfer: bulkTransferRefSchema,
      display_text: optionalStringSchema,
      display_transfer: bulkTransferRefSchema.optional(),
      tag_expansions: z.array(passthroughObjectSchema).optional(),
      forced_skill: optionalStringSchema,
      run_invocation_options: z
        .object({
          max_turns: z.number().int().positive().optional(),
          timeout_ms: positiveSafeU64NumberSchema.optional(),
          approval_mode: z.enum(["manual", "auto", "yolo"]).optional(),
        })
        .strict()
        .optional(),
    })
    .strict()
    .superRefine((value, ctx) => {
      if (
        (value.expected_model_state_generation === undefined) !==
        (value.expected_model === undefined)
      ) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "expected model generation and identity must be supplied together",
        });
      }
      const sourceMinimumBytes = value.display_transfer === undefined ? 65_537 : 1;
      const bytes = Number(value.transfer.total_length);
      if (
        value.transfer.mime_class !== "opaque" ||
        !Number.isSafeInteger(bytes) ||
        bytes < sourceMinimumBytes ||
        bytes > 8 * 1024 * 1024
      ) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "bulk user message must be an opaque 64KiB..8MiB transfer",
        });
      }
      if (value.display_text !== undefined && value.display_transfer !== undefined) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "bulk user message display text must be inline or a transfer, not both",
        });
      }
      if (new TextEncoder().encode(value.display_text ?? "").length > 64 * 1024) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "bulk user message display text over 64KiB must use a transfer",
        });
      }
      if (value.display_transfer) {
        const displayBytes = Number(value.display_transfer.total_length);
        if (
          value.display_transfer.mime_class !== "opaque" ||
          !Number.isSafeInteger(displayBytes) ||
          displayBytes < 1 ||
          displayBytes > 8 * 1024 * 1024
        ) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: "bulk user message display transfer must be an opaque 1B..8MiB transfer",
          });
        }
        if (value.display_transfer.transfer_id === value.transfer.transfer_id) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: "bulk user message text and display transfers must be distinct",
          });
        }
      }
    }),
  get_run_invocation_status: z.object({ client_submission_id: clientSubmissionIdSchema }).strict(),
  operation_status: z.object({ operation_id: uuidV7Schema }).strict(),
  cancel_run_invocation: z.object({ client_submission_id: clientSubmissionIdSchema }).strict(),
  session_live_status: z.object({ session_ids: z.array(uuidSchema) }).strict(),
  // `provider`/`model` are absent exactly when `clear` is set; the daemon
  // rejects any other combination. It derives the target layer from the
  // authenticated attachment, never from the request.
  set_default_model: z
    .object({
      default_update_id: uuidSchema,
      provider: z.string().min(1).optional(),
      model: z.string().min(1).optional(),
      reasoning_effort: z.string().min(1).optional(),
      thinking_mode: thinkingModeSchema.optional(),
      prompt_cache_retention: promptCacheRetentionSchema.optional(),
      clear: z.boolean().optional(),
    })
    .strict()
    .refine(
      (params) =>
        params.clear === true
          ? params.provider === undefined && params.model === undefined
          : params.provider !== undefined && params.model !== undefined,
      { message: "provider and model are required unless clear is set" },
    ),
  set_model_favorite: z
    .object({
      provider: z.string().min(1),
      model: z.string().min(1),
      favorite: z.boolean(),
    })
    .strict(),
  set_active_model: z
    .object({
      selection_id: uuidSchema,
      provider: z.string().min(1),
      model: z.string().min(1),
      trigger: activeModelSwitchTriggerSchema.optional(),
      reasoning_effort: z.string().min(1).optional(),
      thinking_mode: thinkingModeSchema.optional(),
      prompt_cache_retention: promptCacheRetentionSchema.optional(),
      persist_as_default: z.boolean(),
    })
    .strict()
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
  import_session_archive: z.object({ transfer: bulkTransferRefSchema }).strict(),
  write_bulk_transfer_chunk: z
    .object({
      transfer: bulkTransferRefSchema,
      chunk_index: u32Schema,
      data_base64: z.string(),
    })
    .strict(),
  read_bulk_transfer_chunk: z
    .object({
      transfer_id: opaqueProtocolIdSchema,
      chunk_index: u32Schema,
    })
    .strict(),
  // v10-only owner-remoted type-bound reader for a REDACTED export transfer.
  read_redacted_export_chunk: z
    .object({
      transfer_id: opaqueProtocolIdSchema,
      chunk_index: u32Schema,
    })
    .strict(),
} as const;

type RequestParamSchemas = typeof requestParamSchemas;
type RequestVariant<Name extends keyof RequestParamSchemas> =
  z.infer<RequestParamSchemas[Name]> extends undefined
    ? { request: Name; params?: undefined }
    : {
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

function requestVariantNoParams<Name extends RequestName>(request: Name) {
  return z.object({ request: z.literal(request) }).strict();
}

// Kept as its own array (rather than reading `clientRequestSchema.options`)
// because `clientRequestSchema` is annotated as the wider `z.ZodType<...>`
// below for external callers, which erases the discriminated-union member
// type and, with it, `.options`. `clientEnvelopeSchema` below reuses this
// array directly so it stays in sync with `clientRequestSchema` by
// construction.
const clientRequestVariants = [
  requestVariant("get_app_flag", requestParamSchemas.get_app_flag),
  requestVariant("get_startup_disclosures", requestParamSchemas.get_startup_disclosures),
  requestVariant("mark_app_flag_seen", requestParamSchemas.mark_app_flag_seen),
  requestVariant("resolve_assistant_session", requestParamSchemas.resolve_assistant_session),
  requestVariant("set_workspace_trust", requestParamSchemas.set_workspace_trust),
  requestVariant("archive_session", requestParamSchemas.archive_session),
  requestVariant("import_session_archive", requestParamSchemas.import_session_archive),
  requestVariant("write_bulk_transfer_chunk", requestParamSchemas.write_bulk_transfer_chunk),
  requestVariant("read_bulk_transfer_chunk", requestParamSchemas.read_bulk_transfer_chunk),
  requestVariant("read_redacted_export_chunk", requestParamSchemas.read_redacted_export_chunk),
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
  requestVariant("get_inventory_bundle", requestParamSchemas.get_inventory_bundle),
  requestVariant("get_session_setup_snapshot", requestParamSchemas.get_session_setup_snapshot),
  requestVariant("list_sessions", requestParamSchemas.list_sessions),
  requestVariant("read_history_page", requestParamSchemas.read_history_page),
  requestVariant("read_agent_tree", requestParamSchemas.read_agent_tree),
  requestVariant("read_agent_attention", requestParamSchemas.read_agent_attention),
  requestVariant("read_session_messages", requestParamSchemas.read_session_messages),
  requestVariant("read_subagent_history_page", requestParamSchemas.read_subagent_history_page),
  requestVariant("resolve_agent_decision", requestParamSchemas.resolve_agent_decision),
  requestVariant("rename_session", requestParamSchemas.rename_session),
  requestVariant("resolve_interrupt", requestParamSchemas.resolve_interrupt),
  requestVariantNoParams("restart_if_idle"),
  requestVariant("resume_paused_work", requestParamSchemas.resume_paused_work),
  requestVariant("send_user_message", requestParamSchemas.send_user_message),
  requestVariant("send_user_message_bulk", requestParamSchemas.send_user_message_bulk),
  requestVariant("get_run_invocation_status", requestParamSchemas.get_run_invocation_status),
  requestVariant("operation_status", requestParamSchemas.operation_status),
  requestVariant("cancel_run_invocation", requestParamSchemas.cancel_run_invocation),
  requestVariant("session_live_status", requestParamSchemas.session_live_status),
  requestVariant("set_default_model", requestParamSchemas.set_default_model),
  requestVariant("set_model_favorite", requestParamSchemas.set_model_favorite),
  requestVariant("set_active_model", requestParamSchemas.set_active_model),
  requestVariant("set_agent", requestParamSchemas.set_agent),
  requestVariant("share_session", requestParamSchemas.share_session),
  requestVariant("stats_rollup", requestParamSchemas.stats_rollup),
  requestVariant("unarchive_session", requestParamSchemas.unarchive_session),
] as const;

export const clientRequestSchema: z.ZodType<ClientRequest> = z.discriminatedUnion(
  "request",
  clientRequestVariants,
);

// Built as a single strict object per request variant (envelope fields merged
// directly into each member) rather than `z.intersection(envelopeShape,
// clientRequestSchema)`. zod's intersection only reports an `unrecognized_keys`
// issue when BOTH sides flag the same key name, regardless of path; since the
// envelope-only schema has no `params` field at all, it never co-flags a
// bogus key nested inside `params`, so unknown keys inside `params` silently
// passed through. Merging into one object schema per variant makes the
// nested `.strict()` on `params` the sole source of truth again.
const clientEnvelopeVariants = clientRequestVariants.map((variant) =>
  z
    .object({
      v: z.literal(PROTOCOL_VERSION),
      kind: z.literal("req"),
      id: requestIdSchema,
      operation: remoteOperationIdentityV1Schema.optional(),
      ...variant.shape,
    })
    .strict(),
);
export const clientEnvelopeSchema = z.discriminatedUnion(
  "request",
  // `.map` widens the source tuple to a plain array; cast back to the
  // non-empty tuple shape `z.discriminatedUnion` expects. Safe because
  // `clientRequestVariants` is a statically-known non-empty literal array.
  clientEnvelopeVariants as [
    (typeof clientEnvelopeVariants)[number],
    ...(typeof clientEnvelopeVariants)[number][],
  ],
);
export type ClientEnvelope = z.infer<typeof clientEnvelopeSchema>;

export const runInvocationLifecycleStateSchema = z.enum([
  "not_found",
  "accepted",
  "queued",
  "dispatching",
  "submission_unknown",
  "running",
  "cancellation_requested",
  "succeeded",
  "failed",
  "cancelled",
  "timeout_expired",
  "max_turns_exceeded",
  "clock_rollback_timed_out",
  "outcome_unknown",
]);
export type RunInvocationLifecycleState = z.infer<typeof runInvocationLifecycleStateSchema>;
export const runInvocationTerminalReasonSchema = z.enum([
  "succeeded",
  "failed",
  "cancelled",
  "cancelled_session_deleted",
  "timeout_expired",
  "max_turns_exceeded",
  "clock_rollback_timed_out",
  "outcome_unknown",
]);
export const runInvocationStatusV1Schema = z
  .object({
    schema_version: z.literal(1),
    client_submission_id: uuidSchema,
    state: runInvocationLifecycleStateSchema,
    state_version: safeU64NumberSchema,
    created_at_wall_ms: safeI64NumberSchema,
    updated_at_wall_ms: safeI64NumberSchema,
    max_turns: z.number().int().positive().nullable().optional(),
    timeout_ms: positiveSafeU64NumberSchema.nullable().optional(),
    remaining_ms: safeU64NumberSchema.nullable().optional(),
    reserved_turns: z.number().int().nonnegative(),
    terminal_at_wall_ms: safeI64NumberSchema.nullable().optional(),
    terminal_reason: runInvocationTerminalReasonSchema.nullable().optional(),
  })
  .strict();
export type RunInvocationStatusV1 = z.infer<typeof runInvocationStatusV1Schema>;
export const runInvocationCancelResultV1Schema = z
  .object({
    schema_version: z.literal(1),
    client_submission_id: uuidSchema,
    outcome: z.enum([
      "cancellation_requested",
      "already_cancelled",
      "already_terminal",
      "not_found",
    ]),
    state: runInvocationLifecycleStateSchema,
    state_version: safeU64NumberSchema,
  })
  .strict();
export type RunInvocationCancelResultV1 = z.infer<typeof runInvocationCancelResultV1Schema>;

export const responseNameSchema = z.enum([
  "ack",
  "app_flag",
  "app_flag_seen",
  "assistant_session_resolved",
  "config_refreshed",
  "attached",
  "forked",
  "fs_list",
  "fs_read",
  "fs_stat",
  "fs_write",
  "git_diff_file",
  "git_status",
  "agent_tree_page",
  "agent_attention_page",
  "agent_decision_steered",
  "history_page",
  "inventory_bundle",
  "session_setup_snapshot",
  "models",
  "restart_decision",
  "run_invocation_status",
  "remote_operation_status",
  "run_invocation_cancel_result",
  "session_messages",
  "session_live_status",
  "sessions",
  "stats_rollup",
  "startup_disclosures",
  "subagent_history_page",
  "user_message_queued",
  "export_session_data",
  "bulk_transfer_chunk_accepted",
  "bulk_transfer_chunk",
  "workspace_trust_set",
]);
export type ResponseName = z.infer<typeof responseNameSchema>;

const responseBaseSchema = {
  v: z.literal(PROTOCOL_VERSION),
  kind: z.literal("res"),
  id: requestIdSchema,
} as const;
export const sessionMessageSchema = z
  .object({
    seq: safeI64NumberSchema,
    ts_ms: safeI64NumberSchema,
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
      seq: safeI64NumberSchema.optional(),
    })
    .passthrough(),
  z
    .object({
      role: z.literal("user"),
      text: z.string(),
      display_text: z.string().optional(),
      tag_expansions: z.array(passthroughObjectSchema).optional(),
      client_submission_ids: z.array(uuidSchema).optional(),
      ts_ms: safeI64NumberSchema.optional(),
      seq: safeI64NumberSchema.optional(),
      origin_principal: z.string().optional(),
    })
    .passthrough(),
  z
    .object({
      role: z.literal("user_note"),
      text: z.string(),
      ts_ms: safeI64NumberSchema.optional(),
      seq: safeI64NumberSchema.optional(),
    })
    .passthrough(),
  z
    .object({
      role: z.literal("assistant"),
      agent: z.string(),
      text: z.string(),
      presentation_text: z.string().optional(),
      reasoning: z.string().optional(),
      response_performance: z
        .object({
          ttft_ms: safeU64NumberSchema,
          generation_ms: safeU64NumberSchema,
          displayed_tokens: safeU64NumberSchema,
          encoding: z.string(),
        })
        .passthrough()
        .optional(),
      ts_ms: safeI64NumberSchema.optional(),
      seq: safeI64NumberSchema.optional(),
    })
    .passthrough(),
  z
    .object({
      role: z.literal("tool_call"),
      seq: safeI64NumberSchema.optional(),
      agent: z.string(),
      call_id: z.string(),
      parent_call_id: z.string().nullable().optional(),
      parent_child_index: safeI64NumberSchema.nullable().optional(),
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
      seq: safeI64NumberSchema.optional(),
      summary: z.string(),
      detail: z.string().optional(),
    })
    .passthrough(),
  z
    .object({
      role: z.literal("compact_boundary"),
      seq: safeI64NumberSchema.optional(),
      predecessor_short_id: z.string(),
      seed_tool_count: z.number().int().nonnegative(),
      seed_tool_tokens: safeU64NumberSchema,
      source: z.string().optional(),
      trigger_ctx_pct: z.number().nullable().optional(),
      tokens_before: safeU64NumberSchema.optional(),
      tokens_after: safeU64NumberSchema.optional(),
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
      seq: safeI64NumberSchema.optional(),
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
    session_entry_mode: sessionEntryModeSchema,
    project_root: projectRootSchema,
    project_id: z.string(),
    started_at_unix_ms: safeI64NumberSchema,
    last_active_at_unix_ms: safeI64NumberSchema,
    turns: safeU64NumberSchema,
    active_agent: z.string(),
  })
  .passthrough();
const fsEntryWireSchema = z
  .object({
    name: z.string(),
    path: z.string(),
    kind: z.enum(["file", "directory", "symlink", "other"]),
    size: safeU64NumberSchema,
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
export const queueTargetSchema = z
  .object({
    id: z.string(),
    agent: z.string(),
    depth: z.number().int().nonnegative(),
    task_call_id: z.string().optional(),
  })
  .passthrough();
export type QueueTarget = z.infer<typeof queueTargetSchema>;
export const queueDeliveryClassSchema = z.enum(["steering", "held"]);
export type QueueDeliveryClass = z.infer<typeof queueDeliveryClassSchema>;
export const queueItemSchema = z
  .object({
    id: uuidSchema,
    status: z.enum(["queued", "folding"]),
    text: z.string(),
    display_text: z.string().optional(),
    target: queueTargetSchema,
    delivery_class: queueDeliveryClassSchema.default("steering"),
  })
  .passthrough();
export type QueueItem = z.infer<typeof queueItemSchema>;
export const resumeRepairActionSchema = z.enum([
  "open_read_only",
  "fork_from_last_provider_valid_turn",
  "repair_synthetic_tool_results",
  "export_debug_bundle",
  "cancel",
]);
export type ResumeRepairAction = z.infer<typeof resumeRepairActionSchema>;
export const resumeRepairStateSchema = z
  .object({
    session_id: uuidSchema,
    short_id: z.string(),
    provider: z.string(),
    model: z.string(),
    wire_api: z.string(),
    failure_kind: z.string().min(1),
    failing_tool_call_ids: z.array(z.string()),
    safe_last_turn_seq: safeI64NumberSchema.optional(),
    suggested_actions: z.array(resumeRepairActionSchema),
    detail: z.string(),
  })
  .passthrough();
export type ResumeRepairState = z.infer<typeof resumeRepairStateSchema>;
export const pausedWorkSummarySchema = z
  .object({
    session_id: uuidSchema,
    active_agent: z.string(),
    project_root: projectRootSchema,
    reason: z.string(),
    pending_tool_count: safeI64NumberSchema,
    daemon_version: z.string(),
    client_version: z.string().optional(),
    updated_at: safeI64NumberSchema,
  })
  .passthrough();
export type PausedWorkSummary = z.infer<typeof pausedWorkSummarySchema>;
export const activeSubagentSchema = z
  .object({
    parent: z.string(),
    child: z.string(),
    task_call_id: z.string(),
    label: z.string(),
  })
  .passthrough();
export type ActiveSubagent = z.infer<typeof activeSubagentSchema>;
export const envSnapshotMetaSchema = z
  .object({
    source: z.enum(["daemon_start", "tui_shell", "tui_process_fallback", "explicit_cli"]),
    digest: z.string(),
    key_count: z.number().int().nonnegative(),
    path_entry_count: z.number().int().nonnegative(),
  })
  .passthrough();
export type EnvSnapshotMeta = z.infer<typeof envSnapshotMetaSchema>;
export const envDiffSummarySchema = z
  .object({
    baseline_digest: z.string(),
    candidate_digest: z.string(),
    added_keys: z.number().int().nonnegative(),
    removed_keys: z.number().int().nonnegative(),
    changed_keys: z.number().int().nonnegative(),
    changed_secret_keys: z.array(z.string()),
    path_added: z.array(z.string()),
    path_removed: z.array(z.string()),
  })
  .passthrough();
export type EnvDiffSummary = z.infer<typeof envDiffSummarySchema>;
export const btwForkInfoSchema = z
  .object({
    session_id: uuidSchema,
    parent_session_id: uuidSchema,
    short_id: z.string().optional(),
    tangent: z.boolean(),
    created_at: safeI64NumberSchema,
    message_count: z.number().int().nonnegative(),
  })
  .passthrough();
export type BtwForkInfo = z.infer<typeof btwForkInfoSchema>;
export const attachedDataSchema = z
  .object({
    session_id: uuidSchema,
    session_entry_mode: sessionEntryModeSchema,
    short_id: z.string(),
    project_root: projectRootSchema,
    project_id: z.string(),
    active_agent: z.string(),
    active_agent_path: z.array(z.string()).optional(),
    foreground_target: queueTargetSchema.optional(),
    active_subagent: activeSubagentSchema.optional(),
    active_model_state: activeModelStateSchema.optional(),
    history: z.array(historyEntryWireSchema),
    paused_work: z.array(pausedWorkSummarySchema),
    repair_required: resumeRepairStateSchema.optional(),
    daemon_version: z.string(),
    compatible: z.boolean(),
    env_baseline: envSnapshotMetaSchema.optional(),
    env_session: envSnapshotMetaSchema.optional(),
    env_drift: envDiffSummarySchema.optional(),
    env_policy_applied: envDriftPolicySchema,
    btw_fork: btwForkInfoSchema.optional(),
  })
  .passthrough();
export type AttachedData = z.infer<typeof attachedDataSchema>;
export const userMessageQueuedResultSchema = z
  .object({ item: queueItemSchema, queue: z.array(queueItemSchema) })
  .passthrough();
export type UserMessageQueuedResult = z.infer<typeof userMessageQueuedResultSchema>;
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
    "app_flag",
    z
      .object({
        key: z.literal("daemon_autostart_notice"),
        seen: z.boolean(),
        version: safeU64NumberSchema,
      })
      .strict(),
  ),
  responseVariant(
    "app_flag_seen",
    z
      .object({
        key: z.literal("daemon_autostart_notice"),
        version: safeU64NumberSchema,
        changed: z.boolean(),
      })
      .strict(),
  ),
  responseVariant(
    "assistant_session_resolved",
    z.object({ session: sessionSummaryWireSchema, created: z.boolean() }).strict(),
  ),
  responseVariant(
    "startup_disclosures",
    z
      .object({
        org_sync: z
          .object({
            org_id: z.string(),
            cursor_seq: safeI64NumberSchema,
            last_synced_at_ms: safeI64NumberSchema.optional(),
          })
          .strict()
          .optional(),
        connector: z
          .object({
            enabled: z.boolean(),
            status: z.string(),
            relay_url: z.string().optional(),
            relay_id: z.string().optional(),
            relay_region: z.string().optional(),
            last_error: z.string().optional(),
          })
          .strict()
          .optional(),
        config_generation: safeU64NumberSchema,
      })
      .strict(),
  ),
  responseVariant(
    "workspace_trust_set",
    z
      .object({
        config_generation: safeU64NumberSchema,
        // Attached sessions that apply the committed decision at their next
        // turn boundary. Omitted when every session applied it immediately.
        live_application_pending: z.array(uuidSchema).optional(),
      })
      .strict(),
  ),
  responseVariant(
    "config_refreshed",
    z.object({ applied_generation: safeU64NumberSchema, changed: z.boolean() }).strict(),
  ),
  responseVariant("attached", attachedDataSchema),
  responseVariant("export_session_data", z.object({ data: exportSessionDataSchema }).passthrough()),
  responseVariant(
    "bulk_transfer_chunk_accepted",
    z
      .object({
        next_chunk_index: u32Schema,
        received_bytes: canonicalU64DecimalStringSchema,
        complete: z.boolean(),
        /** Advertised deadline: how long the daemon holds an idle transfer. */
        idle_timeout_ms: u32Schema,
      })
      .passthrough(),
  ),
  responseVariant(
    "bulk_transfer_chunk",
    z
      .object({
        chunk_index: u32Schema,
        data_base64: z.string(),
        last: z.boolean(),
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
        oldest_seq: safeI64NumberSchema.nullable().optional(),
      })
      .passthrough(),
  ),
  responseVariant(
    "subagent_history_page",
    z
      .object({
        session_id: uuidSchema,
        task_call_id: z.string(),
        label: z.string(),
        entries: z.array(historyEntryWireSchema),
        has_more: z.boolean(),
        oldest_seq: safeI64NumberSchema.nullable().optional(),
      })
      .passthrough(),
  ),
  responseVariant(
    "agent_tree_page",
    z
      .object({
        session_id: nonNilUuidSchema,
        nodes: z.array(agentTreeNodeSchema),
        next_cursor: agentTreeCursorSchema.nullable().optional(),
      })
      .strict(),
  ),
  responseVariant(
    "agent_attention_page",
    z
      .object({
        session_id: nonNilUuidSchema,
        entries: z.array(agentDecisionAttentionSchema),
        next_cursor: agentTreeCursorSchema.nullable().optional(),
      })
      .strict(),
  ),
  responseVariant(
    "agent_decision_steered",
    z
      .object({
        session_id: nonNilUuidSchema,
        decision_request_id: nonNilUuidSchema,
        status: z.enum(["resolved", "steered", "already_terminal", "retry"]),
        decision_state: z.string().min(1),
      })
      .strict(),
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
  responseVariant(
    "inventory_bundle",
    z
      .object({
        agents: z
          .array(
            z
              .object({
                name: z.string().min(1),
                description: z.string(),
                mode: z.string().min(1),
                source: z.string().min(1),
                builtin: z.boolean(),
              })
              .passthrough(),
          )
          .min(0),
        models: z
          .array(
            z
              .object({
                provider: z.string().min(1),
                id: z.string().min(1),
                display_name: z.string(),
                favorite: z.boolean(),
                available: z.boolean(),
                native_provider_valid: z.boolean(),
                trust: z.string().min(1),
              })
              .passthrough(),
          )
          .min(0),
        skills: z
          .array(
            z
              .object({
                name: z.string().min(1),
                description: z.string(),
                source: z.string().min(1),
                user_invocable: z.boolean(),
              })
              .passthrough(),
          )
          .min(0),
        selected_agent: z.string().min(1),
        config_generation: safeU64NumberSchema,
        inventory_generation: safeU64NumberSchema,
        session_generation: safeU64NumberSchema,
      })
      .passthrough(),
  ),
  responseVariant(
    "session_setup_snapshot",
    z
      .object({
        snapshot: z
          .object({
            dto_version: z.literal(1),
            session_id: uuidSchema,
            config_generation: safeU64NumberSchema,
            revision: safeU64NumberSchema,
            selected_installation_id: uuidSchema.optional(),
            candidates: z.array(
              z
                .object({
                  installation: z
                    .object({
                      installation_id: uuidSchema,
                      scope: z.enum(["global", "workspace_private", "workspace_shared"]),
                      source_agent_id: z.string().min(1),
                      source_identity: z.string().min(1),
                      source_revision: z.string().optional(),
                      source_digest: z.string().length(64),
                      installation_revision: safeU64NumberSchema,
                      bindings: z
                        .array(
                          z
                            .object({
                              slot_id: z.string().min(1),
                              state: z.enum([
                                "bound",
                                "primary_unusable",
                                "optional_unbound",
                                "rebind_required",
                              ]),
                              model_id: z.string(),
                            })
                            .strict(),
                        )
                        .optional(),
                    })
                    .strict(),
                  selected: z.boolean(),
                  slots: z
                    .array(
                      z
                        .object({
                          slot_id: z.string().min(1),
                          choices: z
                            .array(
                              z
                                .object({
                                  choice_id: z.string().min(1),
                                  slot_id: z.string().min(1),
                                  offering_id: z.string().min(1),
                                  provider_id: z.string().min(1),
                                  model_id: z.string().min(1),
                                  recommendation_id: z.string().min(1).optional(),
                                  canonical_upstream_identity: z.string().min(1).optional(),
                                  author_label: z.string().min(1).optional(),
                                  rationale: z.string().min(1).optional(),
                                  author_suggested: z.boolean(),
                                  exact_alias_match: z.boolean(),
                                })
                                .strict(),
                            )
                            .optional(),
                          unmatched_recommendations: z
                            .array(
                              z
                                .object({
                                  recommendation_id: z.string().min(1),
                                  canonical_upstream_identity: z.string().min(1),
                                  author_label: z.string().min(1).optional(),
                                  rationale: z.string().min(1).optional(),
                                })
                                .strict(),
                            )
                            .optional(),
                          unavailable_reason: z
                            .enum(["no_hard_compatible_local_model", "rebind_required"])
                            .optional(),
                        })
                        .strict(),
                    )
                    .optional(),
                  locked_reason: z.enum(["definition_unavailable", "rebind_required"]).optional(),
                })
                .strict(),
            ),
          })
          .strict(),
      })
      .strict(),
  ),
  responseVariant("stats_rollup", z.object({ rollup: statsRollupWireSchema }).passthrough()),
  responseVariant(
    "restart_decision",
    z.object({ will_restart: z.boolean(), reason: z.string().optional() }).passthrough(),
  ),
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
  responseVariant("user_message_queued", userMessageQueuedResultSchema),
  responseVariant(
    "run_invocation_status",
    z.object({ status: runInvocationStatusV1Schema }).strict(),
  ),
  responseVariant(
    "remote_operation_status",
    z
      .object({
        status: z
          .object({
            schema_version: z.literal(1),
            operation_id: uuidV7Schema,
            state: z.enum(["reserved", "committed", "rejected", "outcome_unknown"]),
            operation_seq: canonicalU64DecimalStringSchema,
            safe_response: z.array(z.number().int().min(0).max(255)).max(524288).nullable(),
            event_high_water_mark: canonicalU64DecimalStringSchema.nullable(),
          })
          .strict()
          .nullable(),
      })
      .strict(),
  ),
  responseVariant(
    "run_invocation_cancel_result",
    z.object({ result: runInvocationCancelResultV1Schema }).strict(),
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
  "agent_tree_changed",
  "approval_mode_state",
  "assistant_text",
  "assistant_text_delta",
  "assistant_display_text_delta",
  "assistant_display_reasoning_delta",
  "assistant_display_attempt_reset",
  "assistant_display_complete",
  "assistant_display_error",
  "backup_used",
  "caffeinate_state",
  "command_capability_unavailable",
  "compact_ready",
  "config_snapshot",
  "connector_status",
  "context_projection",
  "daemon_draining",
  "default_model_update_result",
  "delegation_recursion_state",
  "env_drift_warning",
  "event_stream_lagged",
  "foreground_input_target",
  "gitignore_allow",
  "goal_supervision_progress",
  "history_replay",
  "host_capabilities_changed",
  "image_control_config_changed",
  "inference_failed",
  "inference_succeeded",
  "inference_warning",
  "interrupt_queue_changed",
  "interrupt_raised",
  "interrupt_resolved",
  "longcache_state",
  "lsp_notice",
  "model_selection_result",
  "nested_turn",
  "notice",
  "osc52_protocol_violation",
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
  "tool_progress",
  "tool_start",
  "usage",
  "user_message_recorded",
  "user_message_retracted",
  "user_messages_terminated",
  "waiting_for_lock",
  "workspace_trust_reconciliation",
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
    max_seq: safeI64NumberSchema,
  })
  .passthrough();
const hostCapabilityFeatureSchema = z
  .object({
    id: z.string().min(1),
    state: z.enum(["available", "missing", "unsupported", "failed"]),
    reason: z.string(),
    fix_command: z.string().optional(),
    remedy_text: z.string().optional(),
    dependency_ids: z.array(z.string().min(1)).optional(),
  })
  .passthrough();
const hostCapabilityDependencySchema = z
  .object({
    id: z.string().min(1),
    state: z.enum([
      "pending",
      "available",
      "missing",
      "incompatible",
      "timed_out",
      "failed",
      "unknown",
      "not_applicable",
    ]),
    importance: z.enum([
      "required_for_default_safety",
      "required_when_feature_selected",
      "optional_integration",
      "optional_accelerator",
    ]),
    target: z.enum(["host", "container"]),
    required_version: z.string().optional(),
    discovered_version: z.string().optional(),
    cause: z.unknown().optional(),
    remedy: z.unknown().optional(),
    reason: z.string(),
  })
  .passthrough();
const hostCapabilitiesChangedDataSchema = z
  .object({
    snapshot: z
      .object({
        generation: safeU64NumberSchema,
        features: z.array(hostCapabilityFeatureSchema),
        dependencies: z.array(hostCapabilityDependencySchema),
        secretStore: z
          .object({
            intent: z.enum(["unconfigured", "database", "keyring"]),
            effective_placement: z.enum(["unavailable", "database", "keyring"]),
            fail_closed_reason: z.string().nullable().optional(),
            fix_command: z.string().nullable().optional(),
          })
          .passthrough(),
      })
      .passthrough(),
  })
  .passthrough();
const interruptResolvedDataSchema = z
  .object({
    session_id: uuidSchema,
    interrupt_id: uuidSchema,
    decision: interruptDecisionSchema.optional(),
    seq: safeI64NumberSchema.optional(),
  })
  .passthrough();
const eventStreamLaggedDataSchema = z
  .object({
    session_id: uuidSchema.optional(),
    dropped: safeU64NumberSchema,
  })
  .passthrough();
const userMessageRecordedDataSchema = z
  .object({
    session_id: uuidSchema,
    seq: safeI64NumberSchema,
    client_submission_ids: z.array(uuidSchema),
    preflight_cleaned: z.string().nullable().optional(),
  })
  .passthrough();
export const userMessageTerminalDispositionSchema = z.enum([
  "removed",
  "cancelled",
  "preflight_rejected",
]);
export const userMessagesTerminatedDataSchema = z
  .object({
    session_id: uuidSchema,
    client_submission_ids: z.array(uuidSchema),
    disposition: userMessageTerminalDispositionSchema,
  })
  .passthrough();
export type UserMessagesTerminatedData = z.infer<typeof userMessagesTerminatedDataSchema>;
const correlatedPreflightDataSchema = z
  .object({
    session_id: uuidSchema,
    client_submission_ids: z.array(uuidSchema),
  })
  .passthrough();
export const queuedUserMessagesFoldedDataSchema = z
  .object({
    session_id: uuidSchema,
    text: z.string(),
    display_text: z.string().optional(),
    tag_expansions: z.array(passthroughObjectSchema).optional(),
    queue_item_ids: z.array(uuidSchema),
    target: queueTargetSchema,
    seq: safeI64NumberSchema.optional(),
    preflight_cleaned: z.string().optional(),
  })
  .passthrough();
export type QueuedUserMessagesFoldedData = z.infer<typeof queuedUserMessagesFoldedDataSchema>;
export const sessionPersistFailedDataSchema = z
  .object({
    session_id: uuidSchema,
    client_submission_id: uuidSchema,
    error: z.string(),
  })
  .passthrough();
export type SessionPersistFailedData = z.infer<typeof sessionPersistFailedDataSchema>;
// The default half of a model selection is only ever `not_requested` or a
// *verified* update: the daemon proves that a post-commit reload of the
// effective configuration resolves to exactly this reference before reporting
// it. There is no "saved without proof" state.
export const defaultModelUpdateOutcomeSchema = z.discriminatedUnion("status", [
  z.object({ status: z.literal("not_requested") }).passthrough(),
  z
    .object({
      status: z.literal("verified"),
      selection: activeModelRefSchema,
      generation: safeU64NumberSchema,
      scope_label: z.string(),
      // Absent means false: the effective default already matched and no
      // bytes were written.
      unchanged: z.boolean().optional(),
    })
    .passthrough(),
]);
export type DefaultModelUpdateOutcome = z.infer<typeof defaultModelUpdateOutcomeSchema>;

/// Terminal outcome of the config-only `set_default_model` operation.
export const defaultModelStandaloneOutcomeSchema = z.discriminatedUnion("status", [
  z
    .object({
      status: z.literal("applied"),
      // Null when the default was cleared and nothing is inherited.
      selection: activeModelRefSchema.nullable().optional(),
      generation: safeU64NumberSchema,
      authority_revision: z.string().regex(/^[a-f0-9]{64}$/),
      scope_label: z.string(),
      unchanged: z.boolean().optional(),
    })
    .passthrough(),
  z
    .object({
      status: z.literal("rejected"),
      user_message: z.string(),
      diagnostic_code: z.string().min(1),
    })
    .passthrough(),
]);
export type DefaultModelStandaloneOutcome = z.infer<typeof defaultModelStandaloneOutcomeSchema>;

export const defaultModelUpdateResultDataSchema = z
  .object({
    session_id: uuidSchema,
    default_update_id: uuidSchema,
    outcome: defaultModelStandaloneOutcomeSchema,
  })
  .passthrough();
export type DefaultModelUpdateResultData = z.infer<typeof defaultModelUpdateResultDataSchema>;

export const modelSelectionOutcomeSchema = z.discriminatedUnion("status", [
  z
    .object({
      status: z.literal("applied"),
      active_state: activeModelStateSchema,
      default_update: defaultModelUpdateOutcomeSchema,
    })
    .passthrough(),
  z
    .object({
      status: z.literal("rejected"),
      user_message: z.string(),
      diagnostic_code: z.string().min(1),
    })
    .passthrough(),
]);
export type ModelSelectionOutcome = z.infer<typeof modelSelectionOutcomeSchema>;

export const modelSelectionResultDataSchema = z
  .object({
    session_id: uuidSchema,
    selection_id: uuidSchema,
    provider: z.string().min(1),
    model: z.string().min(1),
    reasoning_effort: z.string().min(1).optional(),
    thinking_mode: thinkingModeSchema.optional(),
    prompt_cache_retention: promptCacheRetentionSchema.optional(),
    outcome: modelSelectionOutcomeSchema,
  })
  .passthrough();
export type ModelSelectionResultData = z.infer<typeof modelSelectionResultDataSchema>;

const agentTreeChangedDataSchema = z
  .object({
    session_id: nonNilUuidSchema,
    session_event_seq: safeI64NumberSchema,
    transition: z.enum([
      "agent_created",
      "agent_state_changed",
      "attention_raised",
      "attention_state_changed",
      "decision_state_changed",
      "recovery_attached",
    ]),
    // An ordered, state-free invalidation. Consumers fetch the current typed
    // tree/Attention page; a relay must never relabel later mutable state as
    // the snapshot for this edge.
    subject_kind: z.enum(["agent", "decision"]),
    subject_id: nonNilUuidSchema,
  })
  .strict();

// Live reconciliation state for one durable workspace-trust decision. It is
// state-free apart from the revision it names: a relay must never relabel a
// later mutable trust state as the snapshot for this edge.
const workspaceTrustReconciliationDataSchema = z
  .object({
    session_id: nonNilUuidSchema,
    revision: safeI64NumberSchema,
    state: z.enum(["pending", "applied", "stop_retrying", "failed"]),
  })
  .strict();

const structuredEventDataSchemas = {
  active_model_state: activeModelStateSchema.extend({ session_id: uuidSchema }),
  agent_tree_changed: agentTreeChangedDataSchema,
  default_model_update_result: defaultModelUpdateResultDataSchema,
  event_stream_lagged: eventStreamLaggedDataSchema,
  history_replay: historyReplayDataSchema,
  host_capabilities_changed: hostCapabilitiesChangedDataSchema,
  interrupt_raised: interruptRaisedDataSchema,
  model_selection_result: modelSelectionResultDataSchema,
  interrupt_resolved: interruptResolvedDataSchema,
  preflight_started: correlatedPreflightDataSchema,
  queued_user_messages_folded: queuedUserMessagesFoldedDataSchema,
  session_persist_failed: sessionPersistFailedDataSchema,
  user_message_recorded: userMessageRecordedDataSchema,
  user_message_retracted: correlatedPreflightDataSchema,
  user_messages_terminated: userMessagesTerminatedDataSchema,
  workspace_trust_reconciliation: workspaceTrustReconciliationDataSchema,
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
    session_entry_mode: sessionEntryModeSchema,
    short_id: z.string().optional(),
    project_root: projectRootSchema,
    project_id: z.string(),
    started_at_unix_ms: safeI64NumberSchema,
    last_active_at_unix_ms: safeI64NumberSchema,
    turns: safeU64NumberSchema,
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
    size: safeU64NumberSchema,
    mtime_ms: safeI64NumberSchema.nullable().optional(),
    gitignored: z.boolean().optional(),
    blocked: z.boolean().optional(),
    symlink_target: z.string().nullable().optional(),
  })
  .passthrough();
export type FsEntry = z.infer<typeof fsEntrySchema>;

export const listSessionsResultSchema = z
  .object({ sessions: z.array(sessionSummarySchema) })
  .passthrough();
export const attachResultSchema = attachedDataSchema;
export const ackResultSchema = z.unknown();
export const sessionMessagesResultSchema = z
  .object({
    session_id: uuidSchema,
    messages: z.array(sessionMessageSchema),
    has_more: z.boolean(),
  })
  .passthrough();
export const historyPageResultSchema = z
  .object({
    session_id: uuidSchema,
    entries: z.array(historyEntrySchema),
    has_more: z.boolean(),
    oldest_seq: safeI64NumberSchema.nullable().optional(),
  })
  .passthrough();
export const subagentHistoryPageResultSchema = z
  .object({
    session_id: uuidSchema,
    task_call_id: z.string(),
    label: z.string(),
    entries: z.array(historyEntrySchema),
    has_more: z.boolean(),
    oldest_seq: safeI64NumberSchema.nullable().optional(),
  })
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
export type SubagentHistoryPageResult = z.infer<typeof subagentHistoryPageResultSchema>;
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
export function parseUserMessageQueuedResult(value: unknown) {
  return userMessageQueuedResultSchema.parse(value);
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

export * from "./remote-admin-passkey";
export * from "./remote-operation-fcor";
export * from "./remote-protocol-id";
export * from "./remote-signaling-attempt-store";
export * from "./remote-signaling-payloads";
export * from "./remote-transport-lanes";
export * from "./remote-version";
export * from "./remote-webrtc-web-adapter";
