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
  })
  .strict();

export const terminalResizeFrameSchema = z
  .object({
    type: z.literal("terminal.resize"),
    v: z.literal(TERMINAL_PROTOCOL_VERSION),
    cols: z.number().int().min(2).max(1000),
    rows: z.number().int().min(2).max(1000),
  })
  .strict();

export const terminalAttachmentChunkFrameSchema = z
  .object({
    type: z.literal("terminal.attachment_chunk"),
    v: z.literal(TERMINAL_PROTOCOL_VERSION),
    uploadId: z.string().min(1).max(128),
    name: z.string().min(1).max(255),
    mimeType: z.string().min(1).max(120),
    size: z.number().int().min(1).max(TERMINAL_IMAGE_MAX_BYTES),
    offset: z.number().int().min(0),
    dataBase64: z.string().min(1),
    final: z.boolean(),
  })
  .strict();

export const terminalCloseFrameSchema = z
  .object({
    type: z.literal("terminal.close"),
    v: z.literal(TERMINAL_PROTOCOL_VERSION),
  })
  .strict();

export const terminalClientPayloadSchema = z.discriminatedUnion("type", [
  terminalOpenFrameSchema,
  terminalAttachFrameSchema,
  terminalInputFrameSchema,
  terminalResizeFrameSchema,
  terminalAttachmentChunkFrameSchema,
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

export const terminalAttachmentProgressFrameSchema = z
  .object({
    type: z.literal("terminal.attachment_progress"),
    v: z.literal(TERMINAL_PROTOCOL_VERSION),
    uploadId: z.string().min(1).max(128),
    receivedBytes: z.number().int().min(0),
    totalBytes: z.number().int().min(1),
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
  terminalAttachmentProgressFrameSchema,
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
  text?: string;
  files?: readonly FileLike[];
  maxImageBytes?: number;
};

export type TerminalPastePlan =
  | { kind: "text"; text: string }
  | { kind: "images"; images: TerminalPasteItem[] }
  | { kind: "empty" }
  | { kind: "error"; code: "image_too_large" | "unsupported_file"; maxBytes: number };

export function planTerminalPaste(input: TerminalPasteInput): TerminalPastePlan {
  const maxBytes = input.maxImageBytes ?? TERMINAL_IMAGE_MAX_BYTES;
  const files = [...(input.files ?? [])];
  if (files.length > 0) {
    const images: TerminalPasteItem[] = [];
    for (const file of files) {
      if (!isImageFile(file)) return { kind: "error", code: "unsupported_file", maxBytes };
      if (file.size > maxBytes) return { kind: "error", code: "image_too_large", maxBytes };
      images.push({
        kind: "image",
        file,
        name: file.name?.trim() || "pasted-image.png",
      });
    }
    return images.length > 0 ? { kind: "images", images } : { kind: "empty" };
  }
  const text = input.text ?? "";
  return text.length > 0 ? { kind: "text", text } : { kind: "empty" };
}

function isImageFile(file: FileLike) {
  return Boolean(file.type?.startsWith("image/"));
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
