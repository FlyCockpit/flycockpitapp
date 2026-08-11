import { afterEach, describe, expect, it, vi } from "vitest";
import {
  allItemsReady,
  CHUNK_SIZE,
  canAddItems,
  canSend,
  chunkCountForBytes,
  classifyClipboardItems,
  computeHoldsLocalFile,
  computeRequiresLocalBytes,
  type DraftKey,
  emptyMediaDraftState,
  hasItemsRequiringLocalBytes,
  isAllowedTransition,
  kindFromMime,
  MAX_ITEMS_PER_SESSION,
  MAX_PREVIEW_BYTES,
  type MediaDraftItem,
  type MediaDraftState,
  type MediaItemState,
  promotableQueuedItems,
  type RetryCursor,
  readyAttachmentIdentities,
  reduceMediaDraftEvent,
  SUPPORTED_MIME_BY_KIND,
  validatePreviewBody,
} from "./web-media-draft-reducer";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const baseKey: DraftKey = {
  instanceId: "inst-1",
  projectId: "proj-1",
  sessionId: "11111111-1111-4111-8111-111111111111",
  authenticatedDeviceGeneration: 1,
  connectionEpoch: 1,
  draftGeneration: 1,
};

function makeItem(overrides: Partial<MediaDraftItem> = {}): MediaDraftItem {
  return {
    itemId: "draft-1",
    attempt: 1,
    state: "selected",
    kind: "image",
    fileName: "photo.png",
    declaredSize: 1024,
    declaredMime: "image/png",
    digest: null,
    chunkDigests: [],
    chunkCount: null,
    acknowledgedBytes: 0,
    uploadedBytes: 0,
    operationIds: {
      beginId: "00000000-0000-7000-8000-000000000001",
      chunkIds: ["00000000-0000-7000-8000-000000000002"],
      finalizeId: "00000000-0000-7000-8000-000000000003",
      cancelId: "00000000-0000-7000-8000-000000000004",
      discardId: "00000000-0000-7000-8000-000000000005",
    },
    uploadId: null,
    uploadGeneration: null,
    attachmentId: null,
    attachmentVersion: null,
    availabilityGeneration: null,
    error: null,
    retryCursor: null,
    requiresLocalBytes: true,
    holdsLocalFile: true,
    previewUrl: null,
    updatedAt: 0,
    ...overrides,
  };
}

function addItem(
  state: MediaDraftState,
  key: DraftKey = baseKey,
  itemOverrides: Partial<MediaDraftItem> = {},
): MediaDraftState {
  const item = makeItem(itemOverrides);
  return reduceMediaDraftEvent(state, {
    type: "ADD_ITEMS",
    key,
    items: [item],
  });
}

function findItem(
  state: MediaDraftState,
  key: DraftKey = baseKey,
  itemId = "draft-1",
): MediaDraftItem | undefined {
  const k = [
    key.instanceId,
    key.projectId,
    key.sessionId,
    key.authenticatedDeviceGeneration,
    key.connectionEpoch,
    key.draftGeneration,
  ].join(":");
  return state.drafts[k]?.items.find((i) => i.itemId === itemId);
}

function transition(
  state: MediaDraftState,
  key: DraftKey,
  itemId: string,
  to: MediaItemState,
  data?: Partial<MediaDraftItem>,
): MediaDraftState {
  return reduceMediaDraftEvent(state, { type: "TRANSITION", key, itemId, to, data });
}

function staleKey(): DraftKey {
  return { ...baseKey, draftGeneration: 999 };
}

afterEach(() => {
  vi.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// State graph tests
// ---------------------------------------------------------------------------

describe("web_media_draft_reducer state graph", () => {
  it("allows every exact transition in the state graph", () => {
    const valid: Array<[MediaItemState, MediaItemState]> = [
      ["selected", "hashing"],
      ["selected", "cancelled"],
      ["hashing", "queued"],
      ["hashing", "failed"],
      ["hashing", "cancelled"],
      ["queued", "beginning"],
      ["queued", "cancelled"],
      ["beginning", "uploading"],
      ["beginning", "failed"],
      ["beginning", "cancelling"],
      ["uploading", "finalizing"],
      ["uploading", "failed"],
      ["uploading", "cancelling"],
      ["finalizing", "processing"],
      ["finalizing", "failed"],
      ["finalizing", "cancelling"],
      ["processing", "ready"],
      ["processing", "failed"],
      ["processing", "cancelling"],
      ["ready", "removing"],
      ["ready", "sent"],
      ["failed", "recovering"],
      ["failed", "cancelled"],
      ["recovering", "hashing"],
      ["recovering", "queued"],
      ["recovering", "uploading"],
      ["recovering", "finalizing"],
      ["recovering", "processing"],
      ["recovering", "ready"],
      ["recovering", "failed"],
      ["recovering", "cancelled"],
      ["removing", "cancelled"],
      ["removing", "ready"],
      ["removing", "failed"],
      ["cancelling", "cancelled"],
      ["cancelling", "processing"],
      ["cancelling", "ready"],
      ["cancelling", "failed"],
    ];
    for (const [from, to] of valid) {
      expect(isAllowedTransition(from, to), `${from} -> ${to}`).toBe(true);
    }
  });

  it("rejects every regressive or invalid transition", () => {
    const invalid: Array<[MediaItemState, MediaItemState]> = [
      ["selected", "uploading"],
      ["selected", "ready"],
      ["hashing", "beginning"],
      ["hashing", "uploading"],
      ["queued", "uploading"],
      ["queued", "hashing"],
      ["beginning", "processing"],
      ["beginning", "ready"],
      ["uploading", "beginning"],
      ["uploading", "ready"],
      ["finalizing", "uploading"],
      ["finalizing", "ready"],
      ["processing", "uploading"],
      ["processing", "beginning"],
      ["ready", "uploading"],
      ["ready", "hashing"],
      ["ready", "failed"],
      ["sent", "ready"],
      ["sent", "cancelled"],
      ["cancelled", "selected"],
      ["cancelled", "hashing"],
      ["removing", "uploading"],
      ["removing", "hashing"],
    ];
    for (const [from, to] of invalid) {
      expect(isAllowedTransition(from, to), `${from} -> ${to}`).toBe(false);
    }
  });

  it("enforces the state graph in the reducer TRANSITION event", () => {
    let state = emptyMediaDraftState();
    state = addItem(state);
    // Invalid: selected -> uploading (must go through hashing, queued, beginning)
    state = reduceMediaDraftEvent(state, {
      type: "TRANSITION",
      key: baseKey,
      itemId: "draft-1",
      to: "uploading",
    });
    expect(findItem(state)?.state).toBe("selected");

    // Valid path: selected -> hashing -> queued -> beginning -> uploading
    state = transition(state, baseKey, "draft-1", "hashing");
    expect(findItem(state)?.state).toBe("hashing");
    state = transition(state, baseKey, "draft-1", "queued");
    expect(findItem(state)?.state).toBe("queued");
    state = transition(state, baseKey, "draft-1", "beginning");
    expect(findItem(state)?.state).toBe("beginning");
    state = transition(state, baseKey, "draft-1", "uploading");
    expect(findItem(state)?.state).toBe("uploading");
  });
});

// ---------------------------------------------------------------------------
// Limit tests
// ---------------------------------------------------------------------------

describe("web_media_draft_reducer limits", () => {
  it("enforces the 16-item per-session limit", () => {
    let state = emptyMediaDraftState();
    for (let i = 0; i < MAX_ITEMS_PER_SESSION; i++) {
      state = addItem(state, baseKey, { itemId: `draft-${i}` });
    }
    expect(findItem(state, baseKey, "draft-15")).toBeDefined();
    // 17th item should be rejected (all-or-none for the gesture).
    state = addItem(state, baseKey, { itemId: "draft-16" });
    expect(findItem(state, baseKey, "draft-16")).toBeUndefined();
  });

  it("canAddItems respects the 16-item boundary", () => {
    let state = emptyMediaDraftState();
    expect(canAddItems(state, baseKey, 16)).toBe(true);
    expect(canAddItems(state, baseKey, 17)).toBe(false);
    state = addItem(state, baseKey, { itemId: "d1" });
    expect(canAddItems(state, baseKey, 16)).toBe(false);
    expect(canAddItems(state, baseKey, 15)).toBe(true);
  });

  it("enforces 2 concurrent per session and 4 per instance", () => {
    let state = emptyMediaDraftState();
    // Add 4 items to the same session, all queued.
    for (let i = 0; i < 4; i++) {
      state = addItem(state, baseKey, { itemId: `d${i}` });
      state = transition(state, baseKey, `d${i}`, "hashing");
      state = transition(state, baseKey, `d${i}`, "queued");
    }
    // Only 2 should be promotable per session.
    const promotable = promotableQueuedItems(state, baseKey);
    expect(promotable).toHaveLength(2);
    expect(promotable[0]?.itemId).toBe("d0");
    expect(promotable[1]?.itemId).toBe("d1");
  });

  it("enforces 4 per instance across sessions", () => {
    let state = emptyMediaDraftState();
    const keyA = baseKey;
    const keyB: DraftKey = { ...baseKey, sessionId: "22222222-2222-4222-8222-222222222222" };
    // 2 active in session A, 2 active in session B.
    for (const key of [keyA, keyB]) {
      for (let i = 0; i < 2; i++) {
        state = addItem(state, key, { itemId: `d${key.sessionId.slice(0, 1)}${i}` });
        state = transition(state, key, `d${key.sessionId.slice(0, 1)}${i}`, "hashing");
        state = transition(state, key, `d${key.sessionId.slice(0, 1)}${i}`, "queued");
        state = transition(state, key, `d${key.sessionId.slice(0, 1)}${i}`, "beginning");
      }
    }
    // Add 2 more queued in session A.
    for (let i = 2; i < 4; i++) {
      state = addItem(state, keyA, { itemId: `dA${i}` });
      state = transition(state, keyA, `dA${i}`, "hashing");
      state = transition(state, keyA, `dA${i}`, "queued");
    }
    // Instance already has 4 active, so 0 should be promotable even though
    // session A has session slots.
    const promotable = promotableQueuedItems(state, keyA);
    expect(promotable).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// FIFO order tests
// ---------------------------------------------------------------------------

describe("web_media_draft_reducer FIFO order", () => {
  it("preserves insertion order in the items array", () => {
    let state = emptyMediaDraftState();
    for (let i = 0; i < 5; i++) {
      state = addItem(state, baseKey, { itemId: `item-${i}` });
    }
    const k = [
      baseKey.instanceId,
      baseKey.projectId,
      baseKey.sessionId,
      baseKey.authenticatedDeviceGeneration,
      baseKey.connectionEpoch,
      baseKey.draftGeneration,
    ].join(":");
    const items = state.drafts[k]?.items ?? [];
    expect(items.map((i) => i.itemId)).toEqual(["item-0", "item-1", "item-2", "item-3", "item-4"]);
  });

  it("promotes queued items in FIFO order", () => {
    let state = emptyMediaDraftState();
    for (let i = 0; i < 5; i++) {
      state = addItem(state, baseKey, { itemId: `fifo-${i}` });
      state = transition(state, baseKey, `fifo-${i}`, "hashing");
      state = transition(state, baseKey, `fifo-${i}`, "queued");
    }
    const promotable = promotableQueuedItems(state, baseKey);
    expect(promotable.map((i) => i.itemId)).toEqual(["fifo-0", "fifo-1"]);
  });
});

// ---------------------------------------------------------------------------
// Generation / stale event tests
// ---------------------------------------------------------------------------

describe("web_media_draft_reducer generation isolation", () => {
  it("ignores events with a stale draft generation", () => {
    let state = emptyMediaDraftState();
    state = addItem(state, baseKey, { itemId: "d1" });
    state = transition(state, baseKey, "d1", "hashing");
    // Event with a different draft generation should not affect the item.
    state = reduceMediaDraftEvent(state, {
      type: "TRANSITION",
      key: staleKey(),
      itemId: "d1",
      to: "queued",
    });
    expect(findItem(state, baseKey, "d1")?.state).toBe("hashing");
  });

  it("ignores events with a stale session ID", () => {
    let state = emptyMediaDraftState();
    state = addItem(state, baseKey, { itemId: "d1" });
    const wrongSession: DraftKey = {
      ...baseKey,
      sessionId: "99999999-9999-4999-8999-999999999999",
    };
    state = reduceMediaDraftEvent(state, {
      type: "TRANSITION",
      key: wrongSession,
      itemId: "d1",
      to: "hashing",
    });
    expect(findItem(state, baseKey, "d1")?.state).toBe("selected");
  });

  it("ignores events with a stale connection epoch", () => {
    let state = emptyMediaDraftState();
    state = addItem(state, baseKey, { itemId: "d1" });
    const staleEpoch: DraftKey = { ...baseKey, connectionEpoch: 999 };
    state = reduceMediaDraftEvent(state, {
      type: "TRANSITION",
      key: staleEpoch,
      itemId: "d1",
      to: "hashing",
    });
    expect(findItem(state, baseKey, "d1")?.state).toBe("selected");
  });
});

// ---------------------------------------------------------------------------
// Local-byte facts tests
// ---------------------------------------------------------------------------

describe("web_media_draft_reducer local-byte facts", () => {
  it("requiresLocalBytes is true for selected|hashing|queued|beginning|uploading|finalizing", () => {
    for (const state of [
      "selected",
      "hashing",
      "queued",
      "beginning",
      "uploading",
      "finalizing",
    ] as MediaItemState[]) {
      expect(computeRequiresLocalBytes(state, null), state).toBe(true);
    }
  });

  it("requiresLocalBytes is false for processing|ready|removing|sent|cancelled", () => {
    for (const state of [
      "processing",
      "ready",
      "removing",
      "sent",
      "cancelled",
    ] as MediaItemState[]) {
      expect(computeRequiresLocalBytes(state, null), state).toBe(false);
    }
  });

  it("requiresLocalBytes in failed|recovering equals whether the cursor can still hash/send", () => {
    const retryable: RetryCursor[] = [
      "rehash_local",
      "requeue_before_begin",
      "query_upload_status",
    ];
    const terminal: RetryCursor[] = ["query_attachment_status", "terminal"];
    for (const cursor of retryable) {
      expect(computeRequiresLocalBytes("failed", cursor), `failed/${cursor}`).toBe(true);
      expect(computeRequiresLocalBytes("recovering", cursor), `recovering/${cursor}`).toBe(true);
    }
    for (const cursor of terminal) {
      expect(computeRequiresLocalBytes("failed", cursor), `failed/${cursor}`).toBe(false);
      expect(computeRequiresLocalBytes("recovering", cursor), `recovering/${cursor}`).toBe(false);
    }
  });

  it("holdsLocalFile mirrors requiresLocalBytes except at materialized->processing", () => {
    // Before materialization, holdsLocalFile == requiresLocalBytes.
    for (const state of [
      "selected",
      "hashing",
      "queued",
      "beginning",
      "uploading",
      "finalizing",
    ] as MediaItemState[]) {
      expect(computeHoldsLocalFile(state, null)).toBe(computeRequiresLocalBytes(state, null));
    }
    // At processing, both are false (the caller drops the File before publishing).
    expect(computeHoldsLocalFile("processing", null)).toBe(false);
    expect(computeRequiresLocalBytes("processing", null)).toBe(false);
  });

  it("MATERIALIZED sets both requiresLocalBytes and holdsLocalFile to false synchronously", () => {
    let state = emptyMediaDraftState();
    state = addItem(state, baseKey, { itemId: "d1" });
    state = transition(state, baseKey, "d1", "hashing");
    state = transition(state, baseKey, "d1", "queued");
    state = transition(state, baseKey, "d1", "beginning");
    state = transition(state, baseKey, "d1", "uploading");
    state = transition(state, baseKey, "d1", "finalizing");
    state = reduceMediaDraftEvent(state, {
      type: "MATERIALIZED",
      key: baseKey,
      itemId: "d1",
      attachmentId: "att-1",
      attachmentVersion: 1,
      availabilityGeneration: 1,
    });
    const item = findItem(state, baseKey, "d1");
    expect(item?.state).toBe("processing");
    expect(item?.requiresLocalBytes).toBe(false);
    expect(item?.holdsLocalFile).toBe(false);
    expect(item?.attachmentId).toBe("att-1");
    expect(item?.attachmentVersion).toBe(1);
  });

  it("hasItemsRequiringLocalBytes detects any item needing bytes", () => {
    let state = emptyMediaDraftState();
    const k = [
      baseKey.instanceId,
      baseKey.projectId,
      baseKey.sessionId,
      baseKey.authenticatedDeviceGeneration,
      baseKey.connectionEpoch,
      baseKey.draftGeneration,
    ].join(":");
    expect(hasItemsRequiringLocalBytes(state.drafts[k])).toBe(false);
    state = addItem(state, baseKey, { itemId: "d1" });
    expect(hasItemsRequiringLocalBytes(state.drafts[k])).toBe(true);
    state = transition(state, baseKey, "d1", "hashing");
    state = transition(state, baseKey, "d1", "queued");
    state = transition(state, baseKey, "d1", "beginning");
    state = transition(state, baseKey, "d1", "uploading");
    state = transition(state, baseKey, "d1", "finalizing");
    state = reduceMediaDraftEvent(state, {
      type: "MATERIALIZED",
      key: baseKey,
      itemId: "d1",
      attachmentId: "att-1",
      attachmentVersion: 1,
      availabilityGeneration: 1,
    });
    expect(hasItemsRequiringLocalBytes(state.drafts[k])).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Cancellation tests
// ---------------------------------------------------------------------------

describe("web_media_draft_reducer cancellation", () => {
  it("selected|hashing|queued cancel locally to cancelled (no RPC)", () => {
    for (const initialState of ["selected", "hashing", "queued"] as MediaItemState[]) {
      let state = emptyMediaDraftState();
      state = addItem(state, baseKey, { itemId: "d1", state: initialState });
      if (initialState !== "selected") {
        // Items are added in "selected"; simulate prior transitions.
        state = transition(state, baseKey, "d1", initialState as MediaItemState);
      }
      state = reduceMediaDraftEvent(state, { type: "CANCEL_ITEM", key: baseKey, itemId: "d1" });
      expect(findItem(state, baseKey, "d1")?.state).toBe("cancelled");
    }
  });

  it("beginning|uploading|finalizing cancel to cancelling (RPC-bound)", () => {
    for (const initialState of ["beginning", "uploading", "finalizing"] as MediaItemState[]) {
      let state = emptyMediaDraftState();
      state = addItem(state, baseKey, { itemId: "d1" });
      // Walk to the target state.
      state = transition(state, baseKey, "d1", "hashing");
      state = transition(state, baseKey, "d1", "queued");
      state = transition(state, baseKey, "d1", "beginning");
      if (initialState === "uploading" || initialState === "finalizing") {
        state = transition(state, baseKey, "d1", "uploading");
      }
      if (initialState === "finalizing") {
        state = transition(state, baseKey, "d1", "finalizing");
      }
      state = reduceMediaDraftEvent(state, { type: "CANCEL_ITEM", key: baseKey, itemId: "d1" });
      expect(findItem(state, baseKey, "d1")?.state).toBe("cancelling");
    }
  });

  it("processing|removing cancel to cancelling (attachment-discard-bound)", () => {
    let state = emptyMediaDraftState();
    state = addItem(state, baseKey, { itemId: "d1" });
    state = transition(state, baseKey, "d1", "hashing");
    state = transition(state, baseKey, "d1", "queued");
    state = transition(state, baseKey, "d1", "beginning");
    state = transition(state, baseKey, "d1", "uploading");
    state = transition(state, baseKey, "d1", "finalizing");
    state = reduceMediaDraftEvent(state, {
      type: "MATERIALIZED",
      key: baseKey,
      itemId: "d1",
      attachmentId: "att-1",
      attachmentVersion: 1,
      availabilityGeneration: 1,
    });
    expect(findItem(state, baseKey, "d1")?.state).toBe("processing");
    state = reduceMediaDraftEvent(state, { type: "CANCEL_ITEM", key: baseKey, itemId: "d1" });
    expect(findItem(state, baseKey, "d1")?.state).toBe("cancelling");
  });
});

// ---------------------------------------------------------------------------
// Retry / failure tests
// ---------------------------------------------------------------------------

describe("web_media_draft_reducer retry and failure", () => {
  it("records a retry cursor on failure", () => {
    let state = emptyMediaDraftState();
    state = addItem(state, baseKey, { itemId: "d1" });
    state = transition(state, baseKey, "d1", "hashing");
    state = reduceMediaDraftEvent(state, {
      type: "SET_ERROR",
      key: baseKey,
      itemId: "d1",
      error: "hash_read_failed",
      retryCursor: "rehash_local",
    });
    const item = findItem(state, baseKey, "d1");
    expect(item?.state).toBe("failed");
    expect(item?.retryCursor).toBe("rehash_local");
    expect(item?.requiresLocalBytes).toBe(true); // rehash_local still needs bytes
  });

  it("terminal failure sets requiresLocalBytes false", () => {
    let state = emptyMediaDraftState();
    state = addItem(state, baseKey, { itemId: "d1" });
    state = transition(state, baseKey, "d1", "hashing");
    state = transition(state, baseKey, "d1", "queued");
    state = transition(state, baseKey, "d1", "beginning");
    state = transition(state, baseKey, "d1", "uploading");
    state = reduceMediaDraftEvent(state, {
      type: "SET_ERROR",
      key: baseKey,
      itemId: "d1",
      error: "authorization_revoked",
      retryCursor: "terminal",
    });
    const item = findItem(state, baseKey, "d1");
    expect(item?.state).toBe("failed");
    expect(item?.retryCursor).toBe("terminal");
    expect(item?.requiresLocalBytes).toBe(false);
  });

  it("RETRY_ITEM transitions failed -> recovering", () => {
    let state = emptyMediaDraftState();
    state = addItem(state, baseKey, { itemId: "d1" });
    state = transition(state, baseKey, "d1", "hashing");
    state = reduceMediaDraftEvent(state, {
      type: "SET_ERROR",
      key: baseKey,
      itemId: "d1",
      error: "hash_failed",
      retryCursor: "rehash_local",
    });
    state = reduceMediaDraftEvent(state, { type: "RETRY_ITEM", key: baseKey, itemId: "d1" });
    expect(findItem(state, baseKey, "d1")?.state).toBe("recovering");
  });
});

// ---------------------------------------------------------------------------
// Send tests
// ---------------------------------------------------------------------------

describe("web_media_draft_reducer send", () => {
  it("allItemsReady is true when all items are ready", () => {
    let state = emptyMediaDraftState();
    const k = [
      baseKey.instanceId,
      baseKey.projectId,
      baseKey.sessionId,
      baseKey.authenticatedDeviceGeneration,
      baseKey.connectionEpoch,
      baseKey.draftGeneration,
    ].join(":");
    state = addItem(state, baseKey, { itemId: "d1" });
    expect(allItemsReady(state.drafts[k])).toBe(false);
    // Walk to ready.
    state = transition(state, baseKey, "d1", "hashing");
    state = transition(state, baseKey, "d1", "queued");
    state = transition(state, baseKey, "d1", "beginning");
    state = transition(state, baseKey, "d1", "uploading");
    state = transition(state, baseKey, "d1", "finalizing");
    state = reduceMediaDraftEvent(state, {
      type: "MATERIALIZED",
      key: baseKey,
      itemId: "d1",
      attachmentId: "att-1",
      attachmentVersion: 1,
      availabilityGeneration: 1,
    });
    state = reduceMediaDraftEvent(state, {
      type: "READY",
      key: baseKey,
      itemId: "d1",
      attachmentId: "att-1",
      attachmentVersion: 1,
      availabilityGeneration: 2,
    });
    expect(allItemsReady(state.drafts[k])).toBe(true);
  });

  it("readyAttachmentIdentities returns ordered ready identities", () => {
    let state = emptyMediaDraftState();
    const k = [
      baseKey.instanceId,
      baseKey.projectId,
      baseKey.sessionId,
      baseKey.authenticatedDeviceGeneration,
      baseKey.connectionEpoch,
      baseKey.draftGeneration,
    ].join(":");
    state = addItem(state, baseKey, { itemId: "d1", kind: "image", digest: "abc123" });
    state = transition(state, baseKey, "d1", "hashing");
    state = reduceMediaDraftEvent(state, {
      type: "HASH_PROGRESS",
      key: baseKey,
      itemId: "d1",
      digest: "abc123",
      chunkDigests: ["chunk1"],
      chunkCount: 1,
    });
    state = transition(state, baseKey, "d1", "queued");
    state = transition(state, baseKey, "d1", "beginning");
    state = transition(state, baseKey, "d1", "uploading");
    state = transition(state, baseKey, "d1", "finalizing");
    state = reduceMediaDraftEvent(state, {
      type: "MATERIALIZED",
      key: baseKey,
      itemId: "d1",
      attachmentId: "att-1",
      attachmentVersion: 1,
      availabilityGeneration: 1,
    });
    state = reduceMediaDraftEvent(state, {
      type: "READY",
      key: baseKey,
      itemId: "d1",
      attachmentId: "att-1",
      attachmentVersion: 1,
      availabilityGeneration: 2,
    });
    const identities = readyAttachmentIdentities(state.drafts[k]);
    expect(identities).toHaveLength(1);
    expect(identities[0]).toEqual({
      attachmentId: "att-1",
      attachmentVersion: 1,
      kind: "image",
      checksum: "abc123",
    });
  });

  it("canSend requires attachment ready, canWrite, and text or ready attachments", () => {
    const k = [
      baseKey.instanceId,
      baseKey.projectId,
      baseKey.sessionId,
      baseKey.authenticatedDeviceGeneration,
      baseKey.connectionEpoch,
      baseKey.draftGeneration,
    ].join(":");
    const emptyDraft = undefined;
    // No attachments, no text -> cannot send.
    expect(canSend(emptyDraft, false, true, true)).toBe(false);
    // No attachments, has text -> can send.
    expect(canSend(emptyDraft, true, true, true)).toBe(true);
    // Not attachment ready -> cannot send.
    expect(canSend(emptyDraft, true, false, true)).toBe(false);
    // Cannot write -> cannot send.
    expect(canSend(emptyDraft, true, true, false)).toBe(false);

    // Draft with non-ready items -> cannot send even with text.
    let state = emptyMediaDraftState();
    state = addItem(state, baseKey, { itemId: "d1" });
    expect(canSend(state.drafts[k], true, true, true)).toBe(false);
  });

  it("SENT transitions ready items to sent and clears preview URLs", () => {
    let state = emptyMediaDraftState();
    state = addItem(state, baseKey, { itemId: "d1" });
    // Walk to ready.
    state = transition(state, baseKey, "d1", "hashing");
    state = transition(state, baseKey, "d1", "queued");
    state = transition(state, baseKey, "d1", "beginning");
    state = transition(state, baseKey, "d1", "uploading");
    state = transition(state, baseKey, "d1", "finalizing");
    state = reduceMediaDraftEvent(state, {
      type: "MATERIALIZED",
      key: baseKey,
      itemId: "d1",
      attachmentId: "att-1",
      attachmentVersion: 1,
      availabilityGeneration: 1,
    });
    state = reduceMediaDraftEvent(state, {
      type: "READY",
      key: baseKey,
      itemId: "d1",
      attachmentId: "att-1",
      attachmentVersion: 1,
      availabilityGeneration: 2,
    });
    state = reduceMediaDraftEvent(state, {
      type: "SET_PREVIEW",
      key: baseKey,
      itemId: "d1",
      previewUrl: "blob:preview-1",
    });
    expect(findItem(state, baseKey, "d1")?.previewUrl).toBe("blob:preview-1");
    state = reduceMediaDraftEvent(state, {
      type: "SENT",
      key: baseKey,
      itemIds: ["d1"],
    });
    expect(findItem(state, baseKey, "d1")?.state).toBe("sent");
    expect(findItem(state, baseKey, "d1")?.previewUrl).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Clipboard classification tests
// ---------------------------------------------------------------------------

describe("web_media_draft_reducer clipboard classification", () => {
  /** Build a mock DataTransferItem list for testing in a Node environment. */
  function mockItems(
    entries: { kind: "string" | "file"; type: string; data?: string; file?: File }[],
  ): DataTransferItem[] {
    return entries.map((e) => ({
      kind: e.kind,
      type: e.type,
      getAsString: (cb: (s: string) => void) => {
        if (e.kind === "string") cb(e.data ?? "");
      },
      getAsFile: (): File | null => (e.kind === "file" ? e.file! : null),
    })) as unknown as DataTransferItem[];
  }

  it("classifies supported media files by MIME hint", () => {
    const file = new File([new Uint8Array([1, 2, 3])], "photo.png", { type: "image/png" });
    const items = mockItems([{ kind: "file", type: "image/png", file }]);
    const result = classifyClipboardItems(items);
    expect(result.mediaFiles).toHaveLength(1);
    expect(result.mediaFiles[0]?.kind).toBe("image");
    expect(result.unsupported).toHaveLength(0);
  });

  it("classifies unsupported files with per-item errors", () => {
    const file = new File([new Uint8Array([1, 2, 3])], "doc.pdf", { type: "application/pdf" });
    const items = mockItems([{ kind: "file", type: "application/pdf", file }]);
    const result = classifyClipboardItems(items);
    expect(result.mediaFiles).toHaveLength(0);
    expect(result.unsupported).toHaveLength(1);
    expect(result.unsupported[0]?.reason).toBe("unsupported_format");
  });

  it("rejects zero-byte files", () => {
    const file = new File([], "empty.png", { type: "image/png" });
    const items = mockItems([{ kind: "file", type: "image/png", file }]);
    const result = classifyClipboardItems(items);
    expect(result.mediaFiles).toHaveLength(0);
    expect(result.unsupported).toHaveLength(1);
    expect(result.unsupported[0]?.reason).toBe("zero_byte_file");
  });

  it("detects plain text string items", () => {
    const items = mockItems([{ kind: "string", type: "text/plain", data: "hello world" }]);
    const result = classifyClipboardItems(items);
    expect(result.plainText).not.toBeNull();
    expect(result.mediaFiles).toHaveLength(0);
  });

  it("never interprets HTML string items", () => {
    const items = mockItems([{ kind: "string", type: "text/html", data: "<b>bold</b>" }]);
    const result = classifyClipboardItems(items);
    expect(result.plainText).toBeNull();
    expect(result.mediaFiles).toHaveLength(0);
  });

  it("handles mixed clipboard with files and text", () => {
    const file = new File([new Uint8Array([1, 2, 3])], "audio.mp3", { type: "audio/mpeg" });
    const items = mockItems([
      { kind: "string", type: "text/plain", data: "hello" },
      { kind: "file", type: "audio/mpeg", file },
    ]);
    const result = classifyClipboardItems(items);
    expect(result.mediaFiles).toHaveLength(1);
    expect(result.mediaFiles[0]?.kind).toBe("audio");
    expect(result.plainText).not.toBeNull();
  });

  it("preserves clipboard order for media files", () => {
    const file1 = new File([new Uint8Array([1])], "a.png", { type: "image/png" });
    const file2 = new File([new Uint8Array([2])], "b.mp3", { type: "audio/mpeg" });
    const file3 = new File([new Uint8Array([3])], "c.mp4", { type: "video/mp4" });
    const items = mockItems([
      { kind: "file", type: "image/png", file: file1 },
      { kind: "file", type: "audio/mpeg", file: file2 },
      { kind: "file", type: "video/mp4", file: file3 },
    ]);
    const result = classifyClipboardItems(items);
    expect(result.mediaFiles.map((f) => f.file.name)).toEqual(["a.png", "b.mp3", "c.mp4"]);
    expect(result.mediaFiles.map((f) => f.kind)).toEqual(["image", "audio", "video"]);
  });
});

// ---------------------------------------------------------------------------
// MIME / kind detection tests
// ---------------------------------------------------------------------------

describe("web_media_draft_reducer kind detection", () => {
  it("detects image kinds from supported MIME types", () => {
    expect(kindFromMime("image/png")).toBe("image");
    expect(kindFromMime("image/jpeg")).toBe("image");
    expect(kindFromMime("image/webp")).toBe("image");
    expect(kindFromMime("image/gif")).toBe("image");
  });

  it("detects audio kinds from supported MIME types", () => {
    expect(kindFromMime("audio/mpeg")).toBe("audio");
    expect(kindFromMime("audio/wav")).toBe("audio");
    expect(kindFromMime("audio/ogg")).toBe("audio");
  });

  it("detects video kinds from supported MIME types", () => {
    expect(kindFromMime("video/mp4")).toBe("video");
    expect(kindFromMime("video/webm")).toBe("video");
    expect(kindFromMime("video/ogg")).toBe("video");
  });

  it("returns null for unsupported MIME types", () => {
    expect(kindFromMime("application/pdf")).toBeNull();
    expect(kindFromMime("text/plain")).toBeNull();
    expect(kindFromMime("")).toBeNull();
  });

  it("SUPPORTED_MIME_BY_KIND covers image, audio, and video", () => {
    expect(SUPPORTED_MIME_BY_KIND.image.length).toBeGreaterThan(0);
    expect(SUPPORTED_MIME_BY_KIND.audio.length).toBeGreaterThan(0);
    expect(SUPPORTED_MIME_BY_KIND.video.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// Chunk computation tests
// ---------------------------------------------------------------------------

describe("web_media_draft_reducer chunk computation", () => {
  it("computes 1 chunk for exactly 256 KiB", () => {
    expect(chunkCountForBytes(CHUNK_SIZE)).toBe(1);
  });

  it("computes 2 chunks for 256 KiB + 1 byte", () => {
    expect(chunkCountForBytes(CHUNK_SIZE + 1)).toBe(2);
  });

  it("computes 0 chunks for zero bytes", () => {
    expect(chunkCountForBytes(0)).toBe(0);
  });

  it("computes correct chunks for non-aligned sizes", () => {
    expect(chunkCountForBytes(1)).toBe(1);
    expect(chunkCountForBytes(CHUNK_SIZE - 1)).toBe(1);
    expect(chunkCountForBytes(CHUNK_SIZE * 3)).toBe(3);
    expect(chunkCountForBytes(CHUNK_SIZE * 3 + 1)).toBe(4);
  });
});

// ---------------------------------------------------------------------------
// Preview validation tests
// ---------------------------------------------------------------------------

describe("web_media_draft_reducer preview validation", () => {
  function makeMinimalPng(width: number, height: number): Uint8Array {
    // Minimal PNG: signature + IHDR chunk (length=13) + IEND chunk.
    const sig = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
    const ihdr = [
      0x00,
      0x00,
      0x00,
      0x0d, // length 13
      0x49,
      0x48,
      0x44,
      0x52, // "IHDR"
      (width >>> 24) & 0xff,
      (width >>> 16) & 0xff,
      (width >>> 8) & 0xff,
      width & 0xff,
      (height >>> 24) & 0xff,
      (height >>> 16) & 0xff,
      (height >>> 8) & 0xff,
      height & 0xff,
      0x08,
      0x02,
      0x00,
      0x00,
      0x00, // bit depth 8, color type 2, compression 0, filter 0, interlace 0
      0x00,
      0x00,
      0x00,
      0x00, // CRC (placeholder)
    ];
    const iend = [0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82];
    return new Uint8Array([...sig, ...ihdr, ...iend]);
  }

  it("rejects non-PNG content type", async () => {
    const png = makeMinimalPng(64, 64);
    const result = await validatePreviewBody(png, "image/jpeg", "no-store", "nosniff", "abc");
    expect(result).toBeNull();
  });

  it("rejects missing nosniff", async () => {
    const png = makeMinimalPng(64, 64);
    const result = await validatePreviewBody(png, "image/png", "no-store", "", "abc");
    expect(result).toBeNull();
  });

  it("rejects missing no-store cache control", async () => {
    const png = makeMinimalPng(64, 64);
    const result = await validatePreviewBody(png, "image/png", "max-age=3600", "nosniff", "abc");
    expect(result).toBeNull();
  });

  it("rejects bad PNG signature", async () => {
    const bad = makeMinimalPng(64, 64);
    bad[0] = 0x00;
    const result = await validatePreviewBody(bad, "image/png", "no-store", "nosniff", "abc");
    expect(result).toBeNull();
  });

  it("rejects IHDR dimensions > 256", async () => {
    const png = makeMinimalPng(257, 64);
    const result = await validatePreviewBody(png, "image/png", "no-store", "nosniff", "abc");
    expect(result).toBeNull();
  });

  it("rejects IHDR dimensions < 1", async () => {
    const png = makeMinimalPng(0, 64);
    const result = await validatePreviewBody(png, "image/png", "no-store", "nosniff", "abc");
    expect(result).toBeNull();
  });

  it("rejects body exceeding 512 KiB", async () => {
    const oversized = new Uint8Array(MAX_PREVIEW_BYTES + 1);
    // Set a valid PNG signature.
    oversized[0] = 0x89;
    oversized[1] = 0x50;
    oversized[2] = 0x4e;
    oversized[3] = 0x47;
    oversized[4] = 0x0d;
    oversized[5] = 0x0a;
    oversized[6] = 0x1a;
    oversized[7] = 0x0a;
    const result = await validatePreviewBody(oversized, "image/png", "no-store", "nosniff", "abc");
    expect(result).toBeNull();
  });

  it("accepts a valid PNG with matching checksum", async () => {
    const png = makeMinimalPng(64, 64);
    const digest = await crypto.subtle.digest("SHA-256", png.buffer.slice(0) as ArrayBuffer);
    const checksum = Array.from(new Uint8Array(digest), (b) =>
      b.toString(16).padStart(2, "0"),
    ).join("");
    const result = await validatePreviewBody(png, "image/png", "no-store", "nosniff", checksum);
    expect(result).not.toBeNull();
  });

  it("rejects a valid PNG with wrong checksum", async () => {
    const png = makeMinimalPng(64, 64);
    const result = await validatePreviewBody(
      png,
      "image/png",
      "no-store",
      "nosniff",
      "0000000000000000000000000000000000000000000000000000000000000000",
    );
    expect(result).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Session isolation tests
// ---------------------------------------------------------------------------

describe("web_media_draft_reducer session isolation", () => {
  it("separate sessions have separate drafts", () => {
    let state = emptyMediaDraftState();
    const keyA = baseKey;
    const keyB: DraftKey = { ...baseKey, sessionId: "22222222-2222-4222-8222-222222222222" };
    state = addItem(state, keyA, { itemId: "a1" });
    state = addItem(state, keyB, { itemId: "b1" });
    expect(findItem(state, keyA, "a1")).toBeDefined();
    expect(findItem(state, keyB, "b1")).toBeDefined();
    expect(findItem(state, keyA, "b1")).toBeUndefined();
    expect(findItem(state, keyB, "a1")).toBeUndefined();
  });

  it("HIDE_SESSION does not mutate or cancel items", () => {
    let state = emptyMediaDraftState();
    state = addItem(state, baseKey, { itemId: "d1" });
    state = transition(state, baseKey, "d1", "hashing");
    const beforeState = findItem(state, baseKey, "d1")?.state;
    state = reduceMediaDraftEvent(state, { type: "HIDE_SESSION", key: baseKey });
    expect(findItem(state, baseKey, "d1")?.state).toBe(beforeState);
  });

  it("DISPOSE_DRAFT removes the draft and revokes preview URLs", () => {
    let state = emptyMediaDraftState();
    state = addItem(state, baseKey, { itemId: "d1" });
    // Walk to ready with a preview URL.
    state = transition(state, baseKey, "d1", "hashing");
    state = transition(state, baseKey, "d1", "queued");
    state = transition(state, baseKey, "d1", "beginning");
    state = transition(state, baseKey, "d1", "uploading");
    state = transition(state, baseKey, "d1", "finalizing");
    state = reduceMediaDraftEvent(state, {
      type: "MATERIALIZED",
      key: baseKey,
      itemId: "d1",
      attachmentId: "att-1",
      attachmentVersion: 1,
      availabilityGeneration: 1,
    });
    state = reduceMediaDraftEvent(state, {
      type: "READY",
      key: baseKey,
      itemId: "d1",
      attachmentId: "att-1",
      attachmentVersion: 1,
      availabilityGeneration: 2,
    });
    state = reduceMediaDraftEvent(state, {
      type: "SET_PREVIEW",
      key: baseKey,
      itemId: "d1",
      previewUrl: "blob:test-preview",
    });
    const revokeSpy = vi.spyOn(URL, "revokeObjectURL");
    state = reduceMediaDraftEvent(state, { type: "DISPOSE_DRAFT", key: baseKey });
    expect(revokeSpy).toHaveBeenCalledWith("blob:test-preview");
    const k = [
      baseKey.instanceId,
      baseKey.projectId,
      baseKey.sessionId,
      baseKey.authenticatedDeviceGeneration,
      baseKey.connectionEpoch,
      baseKey.draftGeneration,
    ].join(":");
    expect(state.drafts[k]).toBeUndefined();
  });

  it("DISPOSE_ALL clears all drafts and revokes all preview URLs", () => {
    let state = emptyMediaDraftState();
    const keyA = baseKey;
    const keyB: DraftKey = { ...baseKey, sessionId: "22222222-2222-4222-8222-222222222222" };
    state = addItem(state, keyA, { itemId: "a1" });
    state = addItem(state, keyB, { itemId: "b1" });
    const revokeSpy = vi.spyOn(URL, "revokeObjectURL");
    state = reduceMediaDraftEvent(state, { type: "DISPOSE_ALL" });
    expect(Object.keys(state.drafts)).toHaveLength(0);
    // No preview URLs were set, so revoke should not be called.
    expect(revokeSpy).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// Upload progress tests
// ---------------------------------------------------------------------------

describe("web_media_draft_reducer upload progress", () => {
  it("UPLOAD_PROGRESS updates acknowledged and uploaded bytes", () => {
    let state = emptyMediaDraftState();
    state = addItem(state, baseKey, { itemId: "d1" });
    state = transition(state, baseKey, "d1", "hashing");
    state = transition(state, baseKey, "d1", "queued");
    state = transition(state, baseKey, "d1", "beginning");
    state = transition(state, baseKey, "d1", "uploading");
    state = reduceMediaDraftEvent(state, {
      type: "UPLOAD_PROGRESS",
      key: baseKey,
      itemId: "d1",
      acknowledgedBytes: 512 * 1024,
      uploadedBytes: 256 * 1024,
    });
    const item = findItem(state, baseKey, "d1");
    expect(item?.acknowledgedBytes).toBe(512 * 1024);
    expect(item?.uploadedBytes).toBe(256 * 1024);
  });

  it("UPLOAD_PROGRESS is ignored when not in uploading or recovering state", () => {
    let state = emptyMediaDraftState();
    state = addItem(state, baseKey, { itemId: "d1" });
    state = reduceMediaDraftEvent(state, {
      type: "UPLOAD_PROGRESS",
      key: baseKey,
      itemId: "d1",
      acknowledgedBytes: 100,
      uploadedBytes: 100,
    });
    expect(findItem(state, baseKey, "d1")?.acknowledgedBytes).toBe(0);
  });

  it("BEGIN_COMMITTED stores upload ID and generation", () => {
    let state = emptyMediaDraftState();
    state = addItem(state, baseKey, { itemId: "d1" });
    state = transition(state, baseKey, "d1", "hashing");
    state = transition(state, baseKey, "d1", "queued");
    state = transition(state, baseKey, "d1", "beginning");
    state = reduceMediaDraftEvent(state, {
      type: "BEGIN_COMMITTED",
      key: baseKey,
      itemId: "d1",
      uploadId: "upload-uuid-1",
      uploadGeneration: 5,
    });
    const item = findItem(state, baseKey, "d1");
    expect(item?.state).toBe("uploading");
    expect(item?.uploadId).toBe("upload-uuid-1");
    expect(item?.uploadGeneration).toBe(5);
  });
});

// ---------------------------------------------------------------------------
// Hash progress tests
// ---------------------------------------------------------------------------

describe("web_media_draft_reducer hash progress", () => {
  it("HASH_PROGRESS stores digest and chunk info during hashing", () => {
    let state = emptyMediaDraftState();
    state = addItem(state, baseKey, { itemId: "d1" });
    state = transition(state, baseKey, "d1", "hashing");
    state = reduceMediaDraftEvent(state, {
      type: "HASH_PROGRESS",
      key: baseKey,
      itemId: "d1",
      digest: "full-digest-hex",
      chunkDigests: ["chunk-0", "chunk-1"],
      chunkCount: 2,
    });
    const item = findItem(state, baseKey, "d1");
    expect(item?.digest).toBe("full-digest-hex");
    expect(item?.chunkDigests).toEqual(["chunk-0", "chunk-1"]);
    expect(item?.chunkCount).toBe(2);
  });

  it("HASH_PROGRESS is ignored when not in hashing state", () => {
    let state = emptyMediaDraftState();
    state = addItem(state, baseKey, { itemId: "d1" });
    state = reduceMediaDraftEvent(state, {
      type: "HASH_PROGRESS",
      key: baseKey,
      itemId: "d1",
      digest: "full-digest-hex",
      chunkDigests: ["chunk-0"],
      chunkCount: 1,
    });
    expect(findItem(state, baseKey, "d1")?.digest).toBeNull();
  });
});
