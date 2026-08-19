import { z } from "zod";

export const TERMINAL_PROTOCOL_VERSION = 1 as const;
export const TERMINAL_IMAGE_MAX_BYTES = 10 * 1024 * 1024;

export const terminalOpenFrameSchema = z
  .object({
    type: z.literal("terminal.open"),
    v: z.literal(TERMINAL_PROTOCOL_VERSION),
    cwd: z.string().min(1).max(4096).optional(),
    cols: z.number().int().min(2).max(1000),
    rows: z.number().int().min(2).max(1000),
  })
  .strict();

export const terminalAttachFrameSchema = z
  .object({
    type: z.literal("terminal.attach"),
    v: z.literal(TERMINAL_PROTOCOL_VERSION),
    terminalId: z.string().min(1).max(128),
    cols: z.number().int().min(2).max(1000),
    rows: z.number().int().min(2).max(1000),
  })
  .strict();

export const terminalInputFrameSchema = z
  .object({
    type: z.literal("terminal.input"),
    v: z.literal(TERMINAL_PROTOCOL_VERSION),
    data: z.string().min(1),
    bindingId: z.string().uuid(),
    bindingEpoch: z.number().int().nonnegative(),
  })
  .strict();

export const terminalResizeFrameSchema = z
  .object({
    type: z.literal("terminal.resize"),
    v: z.literal(TERMINAL_PROTOCOL_VERSION),
    cols: z.number().int().min(2).max(1000),
    rows: z.number().int().min(2).max(1000),
    bindingId: z.string().uuid(),
    bindingEpoch: z.number().int().nonnegative(),
  })
  .strict();

const terminalIngressIdentitySchema = {
  operationId: z.string().uuid(),
  bindingId: z.string().uuid(),
  bindingEpoch: z.number().int().nonnegative(),
} as const;

export const terminalIngressBeginFrameSchema = z
  .object({
    type: z.literal("terminal.ingress_begin"),
    v: z.literal(TERMINAL_PROTOCOL_VERSION),
    ...terminalIngressIdentitySchema,
    mediaType: z.enum(["image/png", "image/jpeg", "image/gif", "image/webp"]),
    size: z.number().int().min(1).max(TERMINAL_IMAGE_MAX_BYTES),
    sha256: z.string().regex(/^[a-f0-9]{64}$/),
  })
  .strict();

export const terminalIngressChunkFrameSchema = z
  .object({
    type: z.literal("terminal.ingress_chunk"),
    v: z.literal(TERMINAL_PROTOCOL_VERSION),
    ...terminalIngressIdentitySchema,
    offset: z.number().int().min(0),
    dataBase64: z.string().min(1),
  })
  .strict();

export const terminalIngressFinishFrameSchema = z
  .object({
    type: z.literal("terminal.ingress_finish"),
    v: z.literal(TERMINAL_PROTOCOL_VERSION),
    ...terminalIngressIdentitySchema,
  })
  .strict();

export const terminalIngressStatusFrameSchema = z
  .object({
    type: z.literal("terminal.ingress_status"),
    v: z.literal(TERMINAL_PROTOCOL_VERSION),
    ...terminalIngressIdentitySchema,
  })
  .strict();

export const terminalIngressAbortFrameSchema = z
  .object({
    type: z.literal("terminal.ingress_abort"),
    v: z.literal(TERMINAL_PROTOCOL_VERSION),
    ...terminalIngressIdentitySchema,
  })
  .strict();

export const terminalCloseFrameSchema = z
  .object({
    type: z.literal("terminal.close"),
    v: z.literal(TERMINAL_PROTOCOL_VERSION),
    bindingId: z.string().uuid(),
    bindingEpoch: z.number().int().nonnegative(),
  })
  .strict();

export const terminalClientPayloadSchema = z.discriminatedUnion("type", [
  terminalOpenFrameSchema,
  terminalAttachFrameSchema,
  terminalInputFrameSchema,
  terminalResizeFrameSchema,
  terminalIngressBeginFrameSchema,
  terminalIngressChunkFrameSchema,
  terminalIngressFinishFrameSchema,
  terminalIngressStatusFrameSchema,
  terminalIngressAbortFrameSchema,
  terminalCloseFrameSchema,
]);
export type TerminalClientPayload = z.infer<typeof terminalClientPayloadSchema>;

export const terminalOpenedFrameSchema = z
  .object({
    type: z.literal("terminal.opened"),
    v: z.literal(TERMINAL_PROTOCOL_VERSION),
    terminalId: z.string().min(1).max(128),
    viewerCount: z.number().int().min(1),
    recording: z.boolean(),
    bindingId: z.string().uuid(),
    bindingEpoch: z.number().int().nonnegative(),
    terminalGeneration: z.number().int().positive(),
  })
  .strict();

export const terminalOutputFrameSchema = z
  .object({
    type: z.literal("terminal.output"),
    v: z.literal(TERMINAL_PROTOCOL_VERSION),
    data: z.string(),
  })
  .strict();

export const terminalClipboardFrameSchema = z
  .object({
    type: z.literal("terminal.clipboard"),
    v: z.literal(TERMINAL_PROTOCOL_VERSION),
    text: z.string(),
  })
  .strict();

export const terminalIngressStateFrameSchema = z
  .object({
    type: z.literal("terminal.ingress_state"),
    v: z.literal(TERMINAL_PROTOCOL_VERSION),
    operationId: z.string().uuid(),
    state: z.enum(["prepared", "committed", "no_operation"]),
    nextOffset: z.number().int().nonnegative(),
    inputSequence: z.number().int().positive().optional(),
    expiresAtUnixMs: z.number().int().nonnegative().optional(),
  })
  .strict();

export const terminalErrorFrameSchema = z
  .object({
    type: z.literal("terminal.error"),
    v: z.literal(TERMINAL_PROTOCOL_VERSION),
    code: z.enum(["offline", "scope_denied", "revoked", "bad_frame", "host_error"]),
    message: z.string().max(500).optional(),
  })
  .strict();

export const terminalDaemonPayloadSchema = z.discriminatedUnion("type", [
  terminalOpenedFrameSchema,
  terminalOutputFrameSchema,
  terminalClipboardFrameSchema,
  terminalIngressStateFrameSchema,
  terminalErrorFrameSchema,
]);
export type TerminalDaemonPayload = z.infer<typeof terminalDaemonPayloadSchema>;

export type FileLike = {
  name?: string;
  type?: string;
  size: number;
};

export type TerminalPasteItem = { kind: "image"; file: FileLike; name: string };

export type TerminalPasteInput = {
  files?: readonly FileLike[];
  maxImageBytes?: number;
};

/**
 * Unified terminal ingress error vocabulary (snake_case wire source of truth).
 * Both the paste planner and the FIFO ingress controller map into this single
 * set. The UI boundary resolves each code to one locale key, so there is no
 * dual PascalCase/snake_case maintenance.
 */
export const TERMINAL_INGRESS_ERROR_CODES = [
  "too_many_files",
  "image_too_large",
  "unsupported_file",
  "busy",
  "hash_failed",
  "conflict",
  "upload_failed",
  "materialization_failed",
  "expired",
  "deadline_exceeded",
  "commit_unknown",
  "cleanup_pending",
  "cancelled",
  "terminal_unavailable",
] as const;
export type TerminalIngressErrorCode = (typeof TERMINAL_INGRESS_ERROR_CODES)[number];

export type TerminalPastePlan =
  | { kind: "image"; image: TerminalPasteItem }
  | { kind: "empty" }
  | {
      kind: "error";
      code: TerminalIngressErrorCode;
      maxBytes: number;
    };

export function planTerminalPaste(input: TerminalPasteInput): TerminalPastePlan {
  const maxBytes = input.maxImageBytes ?? TERMINAL_IMAGE_MAX_BYTES;
  const files = [...(input.files ?? [])];
  if (files.length > 1) return { kind: "error", code: "too_many_files", maxBytes };
  if (files.length > 0) {
    const file = files[0];
    if (!file) return { kind: "empty" };
    if (!isImageFile(file)) return { kind: "error", code: "unsupported_file", maxBytes };
    if (file.size < 1 || file.size > maxBytes) {
      return { kind: "error", code: "image_too_large", maxBytes };
    }
    return {
      kind: "image",
      image: {
        kind: "image",
        file,
        name: file.name?.trim() || "pasted-image.png",
      },
    };
  }
  return { kind: "empty" };
}

/**
 * Map a PascalCase controller error code to the unified snake_case vocabulary.
 * The FIFO ingress controller historically emits PascalCase codes; this maps
 * each one to the canonical wire code so the UI boundary and locale keys stay
 * single-vocabulary. Unknown strings collapse to {@link TERMINAL_INGRESS_FALLBACK_CODE}.
 */
export const TERMINAL_INGRESS_FALLBACK_CODE =
  "upload_failed" as const satisfies TerminalIngressErrorCode;

const PASCAL_TO_SNAKE: Readonly<Record<string, TerminalIngressErrorCode>> = {
  TooManyFiles: "too_many_files",
  TooLarge: "image_too_large",
  UnsupportedType: "unsupported_file",
  Busy: "busy",
  HashFailed: "hash_failed",
  Conflict: "conflict",
  UploadFailed: "upload_failed",
  MaterializationFailed: "materialization_failed",
  Expired: "expired",
  DeadlineExceeded: "deadline_exceeded",
  CommitUnknown: "commit_unknown",
  CleanupPending: "cleanup_pending",
  Cancelled: "cancelled",
  TerminalUnavailable: "terminal_unavailable",
};

export function toTerminalIngressErrorCode(value: string): TerminalIngressErrorCode {
  if (isCanonicalIngressCode(value)) return value;
  return PASCAL_TO_SNAKE[value] ?? TERMINAL_INGRESS_FALLBACK_CODE;
}

function isCanonicalIngressCode(value: string): value is TerminalIngressErrorCode {
  return (TERMINAL_INGRESS_ERROR_CODES as readonly string[]).includes(value);
}

function isImageFile(file: FileLike) {
  return (
    file.type === "image/png" ||
    file.type === "image/jpeg" ||
    file.type === "image/gif" ||
    file.type === "image/webp"
  );
}

export class ClipboardWriteRateLimiter {
  private timestamps: number[] = [];

  constructor(
    private readonly maxWrites: number,
    private readonly windowMs: number,
  ) {}

  allow(now = Date.now()): boolean {
    this.timestamps = this.timestamps.filter((timestamp) => now - timestamp < this.windowMs);
    if (this.timestamps.length >= this.maxWrites) return false;
    this.timestamps.push(now);
    return true;
  }
}

export type TerminalReattachState =
  | { status: "new" }
  | { status: "open"; terminalId: string }
  | { status: "reattachable"; terminalId: string }
  | { status: "closed" };

export function terminalReattachReducer(
  state: TerminalReattachState,
  event:
    | { type: "opened"; terminalId: string }
    | { type: "disconnect" }
    | { type: "reattach_failed" }
    | { type: "close" },
): TerminalReattachState {
  if (event.type === "opened") return { status: "open", terminalId: event.terminalId };
  if (event.type === "close") return { status: "closed" };
  if (event.type === "disconnect" && state.status === "open") {
    return { status: "reattachable", terminalId: state.terminalId };
  }
  if (event.type === "reattach_failed") return { status: "new" };
  return state;
}
