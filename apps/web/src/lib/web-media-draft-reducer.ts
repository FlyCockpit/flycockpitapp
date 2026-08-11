/**
 * Pure media-draft reducer for the browser DOM composer.
 *
 * This module owns the exact client state graph for typed-media attachment
 * uploads through the daemon media application protocol. It is intentionally
 * free of React, DOM, WebSocket, and side-effectful I/O so every transition
 * can be tested with injected operation IDs and events — no timing sleeps.
 *
 * Browser File objects live outside serializable reducer state, keyed by
 * `itemId`. The reducer only tracks bounded safe metadata.
 */

import type { CanonicalMediaKind } from "@flycockpit/cockpit-protocol";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Maximum ordered items per session draft (daemon-evaluated policy mirror). */
export const MAX_ITEMS_PER_SESSION = 16;
/** Maximum concurrent upload/processing operations per session. */
export const MAX_CONCURRENT_PER_SESSION = 2;
/** Maximum concurrent upload/processing operations per instance. */
export const MAX_CONCURRENT_PER_INSTANCE = 4;
/** Chunk size for sequential uploads (256 KiB), mirroring daemon policy. */
export const CHUNK_SIZE = 256 * 1024;
/** Maximum chunks per upload (daemon policy mirror). */
export const MAX_CHUNKS = 65_536;
/** Maximum attachment preview byte length (daemon policy mirror). */
export const MAX_PREVIEW_BYTES = 512 * 1024;
/** Maximum preview image dimension (daemon policy mirror). */
export const MAX_PREVIEW_DIMENSION = 256;

// ---------------------------------------------------------------------------
// State types
// ---------------------------------------------------------------------------

/** Exact client state graph for a media draft item. */
export type MediaItemState =
  | "selected"
  | "hashing"
  | "queued"
  | "beginning"
  | "uploading"
  | "finalizing"
  | "processing"
  | "ready"
  | "sent"
  | "failed"
  | "recovering"
  | "removing"
  | "cancelling"
  | "cancelled";

/** Retry cursor recorded on every failure. */
export type RetryCursor =
  | "rehash_local"
  | "requeue_before_begin"
  | "query_upload_status"
  | "query_attachment_status"
  | "terminal";

/** Canonical media kind for the format matrix. */
export type MediaKind = CanonicalMediaKind;

/** Supported MIME types per kind (browser hint only; daemon is authoritative). */
export const SUPPORTED_MIME_BY_KIND: Record<MediaKind, readonly string[]> = {
  image: ["image/png", "image/jpeg", "image/webp", "image/gif"],
  audio: ["audio/mpeg", "audio/wav", "audio/ogg", "audio/webm", "audio/aac", "audio/mp4"],
  video: ["video/mp4", "video/webm", "video/ogg"],
};

/** Stable, distinct UUIDv7 operation IDs for one item attempt. */
export interface ItemOperationIds {
  /** Lazily generated at the protocol-client boundary. */
  beginId: string;
  /** One distinct ID per exact chunk index. */
  chunkIds: string[];
  finalizeId: string;
  cancelId: string;
  discardId: string;
}

/** Safe metadata for a media draft item (no raw bytes, paths, or File refs). */
export interface MediaDraftItem {
  /** The `client_draft_id` bound at Begin; also the tray row key. */
  itemId: string;
  /** Local attempt number; a new user action/config generation creates a new attempt. */
  attempt: number;
  state: MediaItemState;
  kind: MediaKind;
  /** Declared filename hint (never raw media bytes; never in logs/analytics). */
  fileName: string;
  /** Declared size in bytes (hint only; daemon validation is authoritative). */
  declaredSize: number;
  /** Browser MIME hint. */
  declaredMime: string;
  /** SHA-256 of the whole file, set after hashing completes. */
  digest: string | null;
  /** Chunk digests, set as each chunk is hashed. */
  chunkDigests: string[];
  /** Total chunk count, set after hashing completes. */
  chunkCount: number | null;
  /** Bytes acknowledged by the daemon. */
  acknowledgedBytes: number;
  /** Bytes uploaded so far (for determinate progress). */
  uploadedBytes: number;
  /** Stable operation IDs for this attempt. */
  operationIds: ItemOperationIds;
  /** Upload ID returned by Begin (stored after Begin commits). */
  uploadId: string | null;
  /** Upload generation returned by Begin. */
  uploadGeneration: number | null;
  /** Attachment identity returned at materialization. */
  attachmentId: string | null;
  /** Attachment version returned at materialization. */
  attachmentVersion: number | null;
  /** Availability generation from daemon. */
  availabilityGeneration: number | null;
  /** Per-item error reason (safe, no raw bytes). */
  error: string | null;
  /** Retry cursor recorded on failure. */
  retryCursor: RetryCursor | null;
  /**
   * True only while upload bytes may still be needed.
   * `selected|hashing|queued|beginning|uploading|finalizing` -> true.
   * In `failed|recovering`: true iff the cursor can still hash or send an
   * unacknowledged chunk from the original File.
   */
  requiresLocalBytes: boolean;
  /**
   * True only while the original File reference is held.
   * Same matrix as `requiresLocalBytes`, but set false synchronously at
   * the authoritative `materialized -> processing` linearization point.
   */
  holdsLocalFile: boolean;
  /** Daemon-preview Blob URL (only set for ready images with validated preview). */
  previewUrl: string | null;
  /** Timestamp of the last state transition (ms). */
  updatedAt: number;
}

/** Draft key: (instance, project, session, device generation, connection epoch, draft generation). */
export interface DraftKey {
  instanceId: string;
  projectId: string;
  sessionId: string;
  authenticatedDeviceGeneration: number;
  connectionEpoch: number;
  draftGeneration: number;
}

/** One session-keyed media draft. */
export interface MediaDraft {
  key: DraftKey;
  items: MediaDraftItem[];
}

/** Instance-level state containing all session drafts. */
export interface MediaDraftState {
  drafts: Record<string, MediaDraft>;
  /** Counter for generating stable local attempt IDs. */
  nextAttempt: number;
}

// ---------------------------------------------------------------------------
// Transition table
// ---------------------------------------------------------------------------

/**
 * The exact allowed state transitions from the prompt's state graph.
 * Any transition not listed here is rejected.
 */
const ALLOWED_TRANSITIONS: Record<MediaItemState, readonly MediaItemState[]> = {
  selected: ["hashing", "cancelled"],
  hashing: ["queued", "failed", "cancelled"],
  queued: ["beginning", "cancelled"],
  beginning: ["uploading", "failed", "cancelling"],
  uploading: ["finalizing", "failed", "cancelling"],
  finalizing: ["processing", "failed", "cancelling"],
  processing: ["ready", "failed", "cancelling"],
  ready: ["removing", "sent"],
  failed: ["recovering", "cancelled"],
  recovering: [
    "hashing",
    "queued",
    "uploading",
    "finalizing",
    "processing",
    "ready",
    "failed",
    "cancelled",
  ],
  removing: ["cancelled", "ready", "failed"],
  cancelling: ["cancelled", "processing", "ready", "failed"],
  cancelled: [],
  sent: [],
};

/**
 * Returns true iff the transition `from -> to` is allowed by the state graph.
 */
export function isAllowedTransition(from: MediaItemState, to: MediaItemState): boolean {
  return ALLOWED_TRANSITIONS[from].includes(to);
}

// ---------------------------------------------------------------------------
// Local-byte facts
// ---------------------------------------------------------------------------

/** States where local bytes are always required. */
const LOCAL_BYTES_REQUIRED_STATES: ReadonlySet<MediaItemState> = new Set([
  "selected",
  "hashing",
  "queued",
  "beginning",
  "uploading",
  "finalizing",
]);

/** States where the original File is always held. */
const HOLDS_FILE_STATES: ReadonlySet<MediaItemState> = LOCAL_BYTES_REQUIRED_STATES;

/**
 * Computes `requiresLocalBytes` for a given state and retry cursor.
 * In `failed|recovering`, it equals whether the cursor can still hash or
 * send an unacknowledged chunk from the original File.
 */
export function computeRequiresLocalBytes(
  state: MediaItemState,
  retryCursor: RetryCursor | null,
): boolean {
  if (LOCAL_BYTES_REQUIRED_STATES.has(state)) return true;
  if (state === "failed" || state === "recovering") {
    return (
      retryCursor === "rehash_local" ||
      retryCursor === "requeue_before_begin" ||
      retryCursor === "query_upload_status"
    );
  }
  return false;
}

/**
 * Computes `holdsLocalFile` for a given state and retry cursor.
 * Same as `requiresLocalBytes` except it is set false synchronously at
 * the authoritative `materialized -> processing` linearization point
 * (handled by the caller before publishing `processing`).
 */
export function computeHoldsLocalFile(
  state: MediaItemState,
  retryCursor: RetryCursor | null,
): boolean {
  if (HOLDS_FILE_STATES.has(state)) return true;
  if (state === "failed" || state === "recovering") {
    return computeRequiresLocalBytes(state, retryCursor);
  }
  return false;
}

// ---------------------------------------------------------------------------
// Reducer events
// ---------------------------------------------------------------------------

/** Discriminated union of all reducer events. */
export type MediaDraftEvent =
  | { type: "ADD_ITEMS"; key: DraftKey; items: Omit<MediaDraftItem, "updatedAt">[] }
  | { type: "REMOVE_ITEM"; key: DraftKey; itemId: string }
  | { type: "CANCEL_ITEM"; key: DraftKey; itemId: string }
  | { type: "RETRY_ITEM"; key: DraftKey; itemId: string }
  | {
      type: "TRANSITION";
      key: DraftKey;
      itemId: string;
      to: MediaItemState;
      data?: Partial<MediaDraftItem>;
    }
  | {
      type: "HASH_PROGRESS";
      key: DraftKey;
      itemId: string;
      digest: string;
      chunkDigests: string[];
      chunkCount: number;
    }
  | {
      type: "UPLOAD_PROGRESS";
      key: DraftKey;
      itemId: string;
      acknowledgedBytes: number;
      uploadedBytes: number;
    }
  | {
      type: "BEGIN_COMMITTED";
      key: DraftKey;
      itemId: string;
      uploadId: string;
      uploadGeneration: number;
    }
  | {
      type: "MATERIALIZED";
      key: DraftKey;
      itemId: string;
      attachmentId: string;
      attachmentVersion: number;
      availabilityGeneration: number;
    }
  | {
      type: "READY";
      key: DraftKey;
      itemId: string;
      attachmentId: string;
      attachmentVersion: number;
      availabilityGeneration: number;
    }
  | { type: "SENT"; key: DraftKey; itemIds: string[] }
  | { type: "SET_ERROR"; key: DraftKey; itemId: string; error: string; retryCursor: RetryCursor }
  | { type: "SET_PREVIEW"; key: DraftKey; itemId: string; previewUrl: string }
  | { type: "CLEAR_PREVIEW"; key: DraftKey; itemId: string }
  | { type: "HIDE_SESSION"; key: DraftKey }
  | { type: "DISPOSE_DRAFT"; key: DraftKey }
  | { type: "DISPOSE_ALL" };

// ---------------------------------------------------------------------------
// Reducer
// ---------------------------------------------------------------------------

/** The initial empty state. */
export function emptyMediaDraftState(): MediaDraftState {
  return { drafts: {}, nextAttempt: 1 };
}

function draftKeyString(key: DraftKey): string {
  return [
    key.instanceId,
    key.projectId,
    key.sessionId,
    key.authenticatedDeviceGeneration,
    key.connectionEpoch,
    key.draftGeneration,
  ].join(":");
}

function findDraft(state: MediaDraftState, key: DraftKey): MediaDraft | undefined {
  return state.drafts[draftKeyString(key)];
}

function ensureDraft(state: MediaDraftState, key: DraftKey): MediaDraft {
  const k = draftKeyString(key);
  const existing = state.drafts[k];
  if (existing) return existing;
  const draft: MediaDraft = { key, items: [] };
  state.drafts[k] = draft;
  return draft;
}

/**
 * Counts items in states that represent active upload/processing operations
 * across all drafts belonging to the same instance.
 */
function countActiveByInstance(state: MediaDraftState, instanceId: string): number {
  let count = 0;
  for (const draft of Object.values(state.drafts)) {
    if (draft.key.instanceId !== instanceId) continue;
    for (const item of draft.items) {
      if (isUploadProcessingState(item.state)) count++;
    }
  }
  return count;
}

/**
 * Counts items in active upload/processing states within one session draft.
 */
function countActiveBySession(draft: MediaDraft): number {
  return draft.items.filter((item) => isUploadProcessingState(item.state)).length;
}

/** States that count toward concurrent upload/processing limits. */
function isUploadProcessingState(state: MediaItemState): boolean {
  return (
    state === "beginning" ||
    state === "uploading" ||
    state === "finalizing" ||
    state === "processing" ||
    state === "recovering" ||
    state === "cancelling"
  );
}

/**
 * Checks whether adding items would exceed the 16-item per-session limit.
 * Returns true if the addition is within bounds.
 */
export function canAddItems(state: MediaDraftState, key: DraftKey, count: number): boolean {
  const draft = findDraft(state, key);
  const currentCount = draft?.items.length ?? 0;
  return currentCount + count <= MAX_ITEMS_PER_SESSION;
}

/**
 * Returns the items that would be promoted from `queued` to `beginning`
 * given the current concurrency limits. FIFO order.
 */
export function promotableQueuedItems(state: MediaDraftState, key: DraftKey): MediaDraftItem[] {
  const draft = findDraft(state, key);
  if (!draft) return [];
  const sessionActive = countActiveBySession(draft);
  const instanceActive = countActiveByInstance(state, key.instanceId);
  const sessionSlots = MAX_CONCURRENT_PER_SESSION - sessionActive;
  const instanceSlots = MAX_CONCURRENT_PER_INSTANCE - instanceActive;
  const slots = Math.min(sessionSlots, instanceSlots);
  if (slots <= 0) return [];
  return draft.items.filter((item) => item.state === "queued").slice(0, slots);
}

function updateItem(
  draft: MediaDraft,
  itemId: string,
  updater: (item: MediaDraftItem) => MediaDraftItem,
): MediaDraft {
  const index = draft.items.findIndex((item) => item.itemId === itemId);
  if (index === -1) return draft;
  const items = [...draft.items];
  items[index] = updater(items[index]!);
  return { ...draft, items };
}

/**
 * The pure reducer. Returns a new state; never mutates the input.
 *
 * Generation mismatch (different instance/project/session/device/connection/
 * draft generation) causes the event to be ignored — late results update
 * only their exact old draft.
 */
export function reduceMediaDraftEvent(
  prev: MediaDraftState,
  event: MediaDraftEvent,
): MediaDraftState {
  const state: MediaDraftState = {
    drafts: { ...prev.drafts },
    nextAttempt: prev.nextAttempt,
  };

  switch (event.type) {
    case "ADD_ITEMS": {
      if (!canAddItems(state, event.key, event.items.length)) return prev;
      const draft = ensureDraft(state, event.key);
      const newItems: MediaDraftItem[] = event.items.map((item) => ({
        ...item,
        attempt: state.nextAttempt,
        requiresLocalBytes: computeRequiresLocalBytes(item.state, item.retryCursor),
        holdsLocalFile: computeHoldsLocalFile(item.state, item.retryCursor),
        updatedAt: 0,
      }));
      state.nextAttempt += event.items.length;
      state.drafts[draftKeyString(event.key)] = {
        ...draft,
        items: [...draft.items, ...newItems],
      };
      return state;
    }

    case "REMOVE_ITEM": {
      const draft = findDraft(state, event.key);
      if (!draft) return prev;
      const item = draft.items.find((i) => i.itemId === event.itemId);
      if (!item) return prev;
      // `ready -> removing` is the only entry to remove.
      if (item.state !== "ready") return prev;
      const updated = updateItem(draft, event.itemId, (i) => ({
        ...i,
        state: "removing",
        requiresLocalBytes: computeRequiresLocalBytes("removing", i.retryCursor),
        holdsLocalFile: computeHoldsLocalFile("removing", i.retryCursor),
        updatedAt: 0,
      }));
      state.drafts[draftKeyString(event.key)] = updated;
      return state;
    }

    case "CANCEL_ITEM": {
      const draft = findDraft(state, event.key);
      if (!draft) return prev;
      const item = draft.items.find((i) => i.itemId === event.itemId);
      if (!item) return prev;
      // `selected|hashing|queued` cancel locally — no RPC, straight to cancelled.
      if (item.state === "selected" || item.state === "hashing" || item.state === "queued") {
        const updated = updateItem(draft, event.itemId, (i) => ({
          ...i,
          state: "cancelled",
          requiresLocalBytes: false,
          holdsLocalFile: false,
          previewUrl: null,
          updatedAt: 0,
        }));
        state.drafts[draftKeyString(event.key)] = updated;
        return state;
      }
      // `beginning|uploading|finalizing` -> cancelling (RPC-bound).
      if (item.state === "beginning" || item.state === "uploading" || item.state === "finalizing") {
        if (!isAllowedTransition(item.state, "cancelling")) return prev;
        const updated = updateItem(draft, event.itemId, (i) => ({
          ...i,
          state: "cancelling",
          requiresLocalBytes: computeRequiresLocalBytes("cancelling", i.retryCursor),
          holdsLocalFile: computeHoldsLocalFile("cancelling", i.retryCursor),
          updatedAt: 0,
        }));
        state.drafts[draftKeyString(event.key)] = updated;
        return state;
      }
      // `processing|ready|removing` -> cancelling (attachment-discard-bound).
      if (item.state === "processing" || item.state === "removing") {
        if (!isAllowedTransition(item.state, "cancelling")) return prev;
        const updated = updateItem(draft, event.itemId, (i) => ({
          ...i,
          state: "cancelling",
          requiresLocalBytes: false,
          holdsLocalFile: false,
          updatedAt: 0,
        }));
        state.drafts[draftKeyString(event.key)] = updated;
        return state;
      }
      return prev;
    }

    case "RETRY_ITEM": {
      const draft = findDraft(state, event.key);
      if (!draft) return prev;
      const item = draft.items.find((i) => i.itemId === event.itemId);
      if (!item) return prev;
      if (item.state !== "failed") return prev;
      if (!isAllowedTransition("failed", "recovering")) return prev;
      const updated = updateItem(draft, event.itemId, (i) => ({
        ...i,
        state: "recovering",
        error: null,
        requiresLocalBytes: computeRequiresLocalBytes("recovering", i.retryCursor),
        holdsLocalFile: computeHoldsLocalFile("recovering", i.retryCursor),
        updatedAt: 0,
      }));
      state.drafts[draftKeyString(event.key)] = updated;
      return state;
    }

    case "TRANSITION": {
      const draft = findDraft(state, event.key);
      if (!draft) return prev;
      const item = draft.items.find((i) => i.itemId === event.itemId);
      if (!item) return prev;
      if (!isAllowedTransition(item.state, event.to)) return prev;
      const updated = updateItem(draft, event.itemId, (i) => ({
        ...i,
        ...event.data,
        state: event.to,
        requiresLocalBytes: computeRequiresLocalBytes(
          event.to,
          event.data?.retryCursor ?? i.retryCursor,
        ),
        holdsLocalFile: computeHoldsLocalFile(event.to, event.data?.retryCursor ?? i.retryCursor),
        updatedAt: 0,
      }));
      state.drafts[draftKeyString(event.key)] = updated;
      return state;
    }

    case "HASH_PROGRESS": {
      const draft = findDraft(state, event.key);
      if (!draft) return prev;
      const item = draft.items.find((i) => i.itemId === event.itemId);
      if (item?.state !== "hashing") return prev;
      const updated = updateItem(draft, event.itemId, (i) => ({
        ...i,
        digest: event.digest,
        chunkDigests: event.chunkDigests,
        chunkCount: event.chunkCount,
        updatedAt: 0,
      }));
      state.drafts[draftKeyString(event.key)] = updated;
      return state;
    }

    case "UPLOAD_PROGRESS": {
      const draft = findDraft(state, event.key);
      if (!draft) return prev;
      const item = draft.items.find((i) => i.itemId === event.itemId);
      if (!item || (item.state !== "uploading" && item.state !== "recovering")) return prev;
      const updated = updateItem(draft, event.itemId, (i) => ({
        ...i,
        acknowledgedBytes: event.acknowledgedBytes,
        uploadedBytes: event.uploadedBytes,
        updatedAt: 0,
      }));
      state.drafts[draftKeyString(event.key)] = updated;
      return state;
    }

    case "BEGIN_COMMITTED": {
      const draft = findDraft(state, event.key);
      if (!draft) return prev;
      const item = draft.items.find((i) => i.itemId === event.itemId);
      if (!item) return prev;
      if (!isAllowedTransition(item.state, "uploading")) return prev;
      const updated = updateItem(draft, event.itemId, (i) => ({
        ...i,
        state: "uploading",
        uploadId: event.uploadId,
        uploadGeneration: event.uploadGeneration,
        requiresLocalBytes: true,
        holdsLocalFile: true,
        updatedAt: 0,
      }));
      state.drafts[draftKeyString(event.key)] = updated;
      return state;
    }

    case "MATERIALIZED": {
      const draft = findDraft(state, event.key);
      if (!draft) return prev;
      const item = draft.items.find((i) => i.itemId === event.itemId);
      if (!item) return prev;
      // The authoritative `materialized -> processing` linearization point.
      // Synchronously drop all local-byte references before publishing `processing`.
      if (!isAllowedTransition(item.state, "processing")) return prev;
      const updated = updateItem(draft, event.itemId, (i) => ({
        ...i,
        state: "processing",
        attachmentId: event.attachmentId,
        attachmentVersion: event.attachmentVersion,
        availabilityGeneration: event.availabilityGeneration,
        requiresLocalBytes: false,
        holdsLocalFile: false,
        // Local File, hash reader, ArrayBuffers, chunk views, pending
        // callbacks are released by the caller before this publishes.
        // Reducer state only reflects the result.
        error: null,
        retryCursor: null,
        updatedAt: 0,
      }));
      state.drafts[draftKeyString(event.key)] = updated;
      return state;
    }

    case "READY": {
      const draft = findDraft(state, event.key);
      if (!draft) return prev;
      const item = draft.items.find((i) => i.itemId === event.itemId);
      if (!item) return prev;
      if (!isAllowedTransition(item.state, "ready")) return prev;
      const updated = updateItem(draft, event.itemId, (i) => ({
        ...i,
        state: "ready",
        attachmentId: event.attachmentId,
        attachmentVersion: event.attachmentVersion,
        availabilityGeneration: event.availabilityGeneration,
        requiresLocalBytes: false,
        holdsLocalFile: false,
        error: null,
        retryCursor: null,
        updatedAt: 0,
      }));
      state.drafts[draftKeyString(event.key)] = updated;
      return state;
    }

    case "SENT": {
      for (const itemId of event.itemIds) {
        const draft = findDraft(state, event.key);
        if (!draft) continue;
        const item = draft.items.find((i) => i.itemId === itemId);
        if (item?.state !== "ready") continue;
        const updated = updateItem(draft, itemId, (i) => ({
          ...i,
          state: "sent",
          previewUrl: null,
          requiresLocalBytes: false,
          holdsLocalFile: false,
          updatedAt: 0,
        }));
        state.drafts[draftKeyString(event.key)] = updated;
      }
      return state;
    }

    case "SET_ERROR": {
      const draft = findDraft(state, event.key);
      if (!draft) return prev;
      const item = draft.items.find((i) => i.itemId === event.itemId);
      if (!item) return prev;
      if (!isAllowedTransition(item.state, "failed")) return prev;
      const updated = updateItem(draft, event.itemId, (i) => ({
        ...i,
        state: "failed",
        error: event.error,
        retryCursor: event.retryCursor,
        requiresLocalBytes: computeRequiresLocalBytes("failed", event.retryCursor),
        holdsLocalFile: computeHoldsLocalFile("failed", event.retryCursor),
        updatedAt: 0,
      }));
      state.drafts[draftKeyString(event.key)] = updated;
      return state;
    }

    case "SET_PREVIEW": {
      const draft = findDraft(state, event.key);
      if (!draft) return prev;
      const item = draft.items.find((i) => i.itemId === event.itemId);
      if (item?.state !== "ready") return prev;
      const updated = updateItem(draft, event.itemId, (i) => ({
        ...i,
        previewUrl: event.previewUrl,
        updatedAt: 0,
      }));
      state.drafts[draftKeyString(event.key)] = updated;
      return state;
    }

    case "CLEAR_PREVIEW": {
      const draft = findDraft(state, event.key);
      if (!draft) return prev;
      const item = draft.items.find((i) => i.itemId === event.itemId);
      if (!item) return prev;
      const updated = updateItem(draft, event.itemId, (i) => ({
        ...i,
        previewUrl: null,
        updatedAt: 0,
      }));
      state.drafts[draftKeyString(event.key)] = updated;
      return state;
    }

    case "HIDE_SESSION": {
      // Switching sessions hides but does not rebind or cancel the prior draft.
      // The draft remains in state keyed by its exact key; it is simply not
      // shown. No state mutation needed — the view layer filters by key.
      return state;
    }

    case "DISPOSE_DRAFT": {
      const k = draftKeyString(event.key);
      if (!state.drafts[k]) return prev;
      // Revoke any daemon-preview Blob URLs before disposal.
      const draft = state.drafts[k]!;
      for (const item of draft.items) {
        if (item.previewUrl) URL.revokeObjectURL(item.previewUrl);
      }
      delete state.drafts[k];
      return state;
    }

    case "DISPOSE_ALL": {
      for (const draft of Object.values(state.drafts)) {
        for (const item of draft.items) {
          if (item.previewUrl) URL.revokeObjectURL(item.previewUrl);
        }
      }
      return emptyMediaDraftState();
    }

    default:
      return prev;
  }
}

// ---------------------------------------------------------------------------
// View model helpers
// ---------------------------------------------------------------------------

/** Returns true if any item in the draft still requires local bytes. */
export function hasItemsRequiringLocalBytes(draft: MediaDraft | undefined): boolean {
  if (!draft) return false;
  return draft.items.some((item) => item.requiresLocalBytes);
}

/** Returns true iff every item in the draft is in the `ready` state. */
export function allItemsReady(draft: MediaDraft | undefined): boolean {
  if (!draft || draft.items.length === 0) return true;
  return draft.items.every((item) => item.state === "ready");
}

/** Returns the ordered `ready` attachment identities for send. */
export function readyAttachmentIdentities(
  draft: MediaDraft | undefined,
): { attachmentId: string; attachmentVersion: number; kind: MediaKind; checksum: string }[] {
  if (!draft) return [];
  return draft.items
    .filter(
      (item) =>
        item.state === "ready" && item.attachmentId && item.attachmentVersion && item.digest,
    )
    .map((item) => ({
      attachmentId: item.attachmentId!,
      attachmentVersion: item.attachmentVersion!,
      kind: item.kind,
      checksum: item.digest!,
    }));
}

/**
 * Returns true iff send is enabled: has message text OR at least one ready
 * attachment, every tray item is ready, and the connection is current.
 * The `hasMessageText` predicate is imported from the foundation; this
 * helper only checks the attachment/tray portion.
 */
export function canSend(
  draft: MediaDraft | undefined,
  hasMessageText: boolean,
  attachmentReady: boolean,
  canWrite: boolean,
): boolean {
  if (!attachmentReady || !canWrite) return false;
  if (!draft || draft.items.length === 0) return hasMessageText;
  if (!allItemsReady(draft)) return false;
  return hasMessageText || readyAttachmentIdentities(draft).length > 0;
}

// ---------------------------------------------------------------------------
// Clipboard / paste helpers
// ---------------------------------------------------------------------------

/** Result of classifying clipboard or drop items. */
export interface ClipboardClassification {
  /** Supported media files in clipboard order. */
  mediaFiles: { file: File; kind: MediaKind }[];
  /** Plain-text content, if any. */
  plainText: string | null;
  /** Unsupported files with per-item safe errors. */
  unsupported: { fileName: string; reason: string }[];
}

/**
 * Classifies a clipboard/drop operation into supported media files,
 * plain text, and unsupported items. HTML is never interpreted.
 *
 * Files are matched by browser MIME hint only; daemon byte validation is
 * authoritative at upload time.
 */
export function classifyClipboardItems(
  items: DataTransferItemList | DataTransferItem[],
): ClipboardClassification {
  const mediaFiles: { file: File; kind: MediaKind }[] = [];
  const unsupported: { fileName: string; reason: string }[] = [];
  let plainText: string | null = null;
  const seenKinds = new Set<MediaKind>();

  const list = Array.from(items);
  for (const item of list) {
    if (item.kind === "string") {
      if (item.type === "text/plain" && plainText === null) {
        // Defer reading; the caller reads the string async. We record that
        // plain text is present so the caller knows to insert it.
        plainText = ""; // marker: present but not yet read
      }
      // text/html is never interpreted.
      continue;
    }
    if (item.kind === "file") {
      const file = item.getAsFile();
      if (!file) continue;
      if (file.size === 0) {
        unsupported.push({ fileName: file.name, reason: "zero_byte_file" });
        continue;
      }
      const kind = kindFromMime(file.type);
      if (!kind) {
        unsupported.push({ fileName: file.name, reason: "unsupported_format" });
        continue;
      }
      mediaFiles.push({ file, kind });
      seenKinds.add(kind);
    }
  }

  return { mediaFiles, plainText, unsupported };
}

/**
 * Determines the canonical media kind from a browser MIME hint.
 * Returns null for unsupported types.
 */
export function kindFromMime(mime: string): MediaKind | null {
  const lower = mime.toLowerCase();
  for (const kind of ["image", "audio", "video"] as MediaKind[]) {
    if (SUPPORTED_MIME_BY_KIND[kind].includes(lower)) return kind;
  }
  // Fallback: prefix-based detection for ambiguous browser MIME.
  if (lower.startsWith("image/")) return "image";
  if (lower.startsWith("audio/")) return "audio";
  if (lower.startsWith("video/")) return "video";
  return null;
}

/**
 * Computes the number of 256-KiB chunks for a given byte length.
 * A zero-byte file yields 0 chunks (and is rejected before hashing).
 */
export function chunkCountForBytes(bytes: number): number {
  if (bytes <= 0) return 0;
  return Math.ceil(bytes / CHUNK_SIZE);
}

// ---------------------------------------------------------------------------
// Preview validation
// ---------------------------------------------------------------------------

/** PNG signature bytes. */
const PNG_SIGNATURE = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];

/**
 * Validates a daemon-returned preview body before constructing a Blob URL.
 * Requires `image/png`, declared/received length <= 512 KiB, PNG signature,
 * one IHDR declaring 1..256 width/height, no bytes after the capped response,
 * and a Web Crypto SHA-256 equal to the advertised checksum.
 *
 * Returns the validated bytes or null if any check fails. A failure is
 * safe-preview-only and never regresses the ready attachment.
 */
export async function validatePreviewBody(
  body: Uint8Array,
  contentType: string,
  cacheControl: string,
  xContentTypeOptions: string,
  advertisedChecksum: string,
): Promise<Uint8Array | null> {
  // Content-Type must be exactly image/png.
  if (contentType.toLowerCase() !== "image/png") return null;
  // nosniff enforcement.
  if (xContentTypeOptions.toLowerCase() !== "nosniff") return null;
  // no-store cache control.
  if (!cacheControl.toLowerCase().includes("no-store")) return null;
  // Length cap.
  if (body.length > MAX_PREVIEW_BYTES) return null;
  // PNG signature.
  if (body.length < PNG_SIGNATURE.length) return null;
  for (let i = 0; i < PNG_SIGNATURE.length; i++) {
    if (body[i] !== PNG_SIGNATURE[i]) return null;
  }
  // IHDR chunk: PNG chunk layout after the 8-byte signature is
  // 4 bytes length (big-endian), 4 bytes type, data, 4 bytes CRC.
  // IHDR is always the first chunk: length=13, type="IHDR".
  if (body.length < 8 + 25) return null; // signature + IHDR chunk (4+4+13+4=25)
  const ihdrLength = (body[8]! << 24) | (body[9]! << 16) | (body[10]! << 8) | body[11]!;
  if (ihdrLength !== 13) return null;
  const ihdrType = String.fromCharCode(body[12]!, body[13]!, body[14]!, body[15]!);
  if (ihdrType !== "IHDR") return null;
  // Width: bytes 16-19, Height: bytes 20-23 (big-endian).
  const width = (body[16]! << 24) | (body[17]! << 16) | (body[18]! << 8) | body[19]!;
  const height = (body[20]! << 24) | (body[21]! << 16) | (body[22]! << 8) | body[23]!;
  if (width < 1 || width > MAX_PREVIEW_DIMENSION) return null;
  if (height < 1 || height > MAX_PREVIEW_DIMENSION) return null;
  // SHA-256 checksum.
  const digest = await crypto.subtle.digest("SHA-256", body.buffer.slice(0) as ArrayBuffer);
  const digestHex = Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join(
    "",
  );
  if (digestHex !== advertisedChecksum.toLowerCase()) return null;
  return body;
}
