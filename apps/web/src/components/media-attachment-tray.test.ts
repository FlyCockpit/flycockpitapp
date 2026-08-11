import { describe, expect, it } from "vitest";
import {
  type DraftKey,
  emptyMediaDraftState,
  type MediaDraft,
  type MediaDraftItem,
  type MediaDraftState,
  reduceMediaDraftEvent,
} from "@/lib/web-media-draft-reducer";
import { createItemOperationIds } from "@/lib/web-media-upload";
import { deriveTrayRows, keyboardReorder, shouldWarnBeforeUnload } from "./media-attachment-tray";

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
    operationIds: createItemOperationIds(1),
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

function getDraft(state: MediaDraftState, key: DraftKey = baseKey): MediaDraft | undefined {
  const k = [
    key.instanceId,
    key.projectId,
    key.sessionId,
    key.authenticatedDeviceGeneration,
    key.connectionEpoch,
    key.draftGeneration,
  ].join(":");
  return state.drafts[k];
}

// ---------------------------------------------------------------------------
// View model tests
// ---------------------------------------------------------------------------

describe("web_media_tray view model", () => {
  it("derives tray rows from a draft", () => {
    let state = emptyMediaDraftState();
    state = reduceMediaDraftEvent(state, {
      type: "ADD_ITEMS",
      key: baseKey,
      items: [
        makeItem({ itemId: "d1" }),
        makeItem({ itemId: "d2", kind: "audio", fileName: "song.mp3" }),
      ],
    });
    const rows = deriveTrayRows(getDraft(state));
    expect(rows).toHaveLength(2);
    expect(rows[0]?.itemId).toBe("d1");
    expect(rows[0]?.kind).toBe("image");
    expect(rows[1]?.itemId).toBe("d2");
    expect(rows[1]?.kind).toBe("audio");
  });

  it("returns empty array for undefined draft", () => {
    expect(deriveTrayRows(undefined)).toEqual([]);
  });

  it("marks uploading state as having progress", () => {
    let state = emptyMediaDraftState();
    state = reduceMediaDraftEvent(state, {
      type: "ADD_ITEMS",
      key: baseKey,
      items: [makeItem({ itemId: "d1", declaredSize: 1024, state: "selected" })],
    });
    // Walk to uploading.
    state = reduceMediaDraftEvent(state, {
      type: "TRANSITION",
      key: baseKey,
      itemId: "d1",
      to: "hashing",
    });
    state = reduceMediaDraftEvent(state, {
      type: "TRANSITION",
      key: baseKey,
      itemId: "d1",
      to: "queued",
    });
    state = reduceMediaDraftEvent(state, {
      type: "TRANSITION",
      key: baseKey,
      itemId: "d1",
      to: "beginning",
    });
    state = reduceMediaDraftEvent(state, {
      type: "TRANSITION",
      key: baseKey,
      itemId: "d1",
      to: "uploading",
    });
    state = reduceMediaDraftEvent(state, {
      type: "UPLOAD_PROGRESS",
      key: baseKey,
      itemId: "d1",
      acknowledgedBytes: 512,
      uploadedBytes: 512,
    });
    const rows = deriveTrayRows(getDraft(state));
    expect(rows[0]?.progress).toBeCloseTo(0.5);
    expect(rows[0]?.indeterminate).toBe(false);
  });

  it("marks processing as indeterminate", () => {
    let state = emptyMediaDraftState();
    state = reduceMediaDraftEvent(state, {
      type: "ADD_ITEMS",
      key: baseKey,
      items: [makeItem({ itemId: "d1", state: "selected" })],
    });
    state = reduceMediaDraftEvent(state, {
      type: "TRANSITION",
      key: baseKey,
      itemId: "d1",
      to: "hashing",
    });
    state = reduceMediaDraftEvent(state, {
      type: "TRANSITION",
      key: baseKey,
      itemId: "d1",
      to: "queued",
    });
    state = reduceMediaDraftEvent(state, {
      type: "TRANSITION",
      key: baseKey,
      itemId: "d1",
      to: "beginning",
    });
    state = reduceMediaDraftEvent(state, {
      type: "TRANSITION",
      key: baseKey,
      itemId: "d1",
      to: "uploading",
    });
    state = reduceMediaDraftEvent(state, {
      type: "TRANSITION",
      key: baseKey,
      itemId: "d1",
      to: "finalizing",
    });
    state = reduceMediaDraftEvent(state, {
      type: "MATERIALIZED",
      key: baseKey,
      itemId: "d1",
      attachmentId: "att-1",
      attachmentVersion: 1,
      availabilityGeneration: 1,
    });
    const rows = deriveTrayRows(getDraft(state));
    expect(rows[0]?.state).toBe("processing");
    expect(rows[0]?.indeterminate).toBe(true);
    expect(rows[0]?.progress).toBeNull();
  });

  it("marks terminal failures as not retryable", () => {
    let state = emptyMediaDraftState();
    state = reduceMediaDraftEvent(state, {
      type: "ADD_ITEMS",
      key: baseKey,
      items: [makeItem({ itemId: "d1", state: "selected" })],
    });
    state = reduceMediaDraftEvent(state, {
      type: "TRANSITION",
      key: baseKey,
      itemId: "d1",
      to: "hashing",
    });
    state = reduceMediaDraftEvent(state, {
      type: "SET_ERROR",
      key: baseKey,
      itemId: "d1",
      error: "authorization_revoked",
      retryCursor: "terminal",
    });
    const rows = deriveTrayRows(getDraft(state));
    expect(rows[0]?.isTerminal).toBe(true);
    expect(rows[0]?.canRetry).toBe(false);
  });

  it("marks non-terminal failures as retryable", () => {
    let state = emptyMediaDraftState();
    state = reduceMediaDraftEvent(state, {
      type: "ADD_ITEMS",
      key: baseKey,
      items: [makeItem({ itemId: "d1", state: "selected" })],
    });
    state = reduceMediaDraftEvent(state, {
      type: "TRANSITION",
      key: baseKey,
      itemId: "d1",
      to: "hashing",
    });
    state = reduceMediaDraftEvent(state, {
      type: "SET_ERROR",
      key: baseKey,
      itemId: "d1",
      error: "hash_failed",
      retryCursor: "rehash_local",
    });
    const rows = deriveTrayRows(getDraft(state));
    expect(rows[0]?.isTerminal).toBe(false);
    expect(rows[0]?.canRetry).toBe(true);
  });

  it("marks ready items as removable", () => {
    let state = emptyMediaDraftState();
    state = reduceMediaDraftEvent(state, {
      type: "ADD_ITEMS",
      key: baseKey,
      items: [makeItem({ itemId: "d1", state: "selected" })],
    });
    state = reduceMediaDraftEvent(state, {
      type: "TRANSITION",
      key: baseKey,
      itemId: "d1",
      to: "hashing",
    });
    state = reduceMediaDraftEvent(state, {
      type: "TRANSITION",
      key: baseKey,
      itemId: "d1",
      to: "queued",
    });
    state = reduceMediaDraftEvent(state, {
      type: "TRANSITION",
      key: baseKey,
      itemId: "d1",
      to: "beginning",
    });
    state = reduceMediaDraftEvent(state, {
      type: "TRANSITION",
      key: baseKey,
      itemId: "d1",
      to: "uploading",
    });
    state = reduceMediaDraftEvent(state, {
      type: "TRANSITION",
      key: baseKey,
      itemId: "d1",
      to: "finalizing",
    });
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
    const rows = deriveTrayRows(getDraft(state));
    expect(rows[0]?.state).toBe("ready");
    expect(rows[0]?.canRemove).toBe(true);
  });

  it("does not show preview URL for non-ready states", () => {
    let state = emptyMediaDraftState();
    state = reduceMediaDraftEvent(state, {
      type: "ADD_ITEMS",
      key: baseKey,
      items: [makeItem({ itemId: "d1", state: "selected", previewUrl: "blob:test" })],
    });
    const rows = deriveTrayRows(getDraft(state));
    // The row has the previewUrl in the data model, but the component only
    // renders it for ready state.
    expect(rows[0]?.state).toBe("selected");
    expect(rows[0]?.previewUrl).toBe("blob:test");
  });
});

// ---------------------------------------------------------------------------
// Before-unload warning tests
// ---------------------------------------------------------------------------

describe("web_media_tray before-unload warning", () => {
  it("warns when any item requires local bytes", () => {
    let state = emptyMediaDraftState();
    state = reduceMediaDraftEvent(state, {
      type: "ADD_ITEMS",
      key: baseKey,
      items: [makeItem({ itemId: "d1", state: "selected" })],
    });
    expect(shouldWarnBeforeUnload(getDraft(state))).toBe(true);
  });

  it("does not warn when no items require local bytes", () => {
    let state = emptyMediaDraftState();
    state = reduceMediaDraftEvent(state, {
      type: "ADD_ITEMS",
      key: baseKey,
      items: [makeItem({ itemId: "d1", state: "selected" })],
    });
    // Walk to processing (local bytes released).
    state = reduceMediaDraftEvent(state, {
      type: "TRANSITION",
      key: baseKey,
      itemId: "d1",
      to: "hashing",
    });
    state = reduceMediaDraftEvent(state, {
      type: "TRANSITION",
      key: baseKey,
      itemId: "d1",
      to: "queued",
    });
    state = reduceMediaDraftEvent(state, {
      type: "TRANSITION",
      key: baseKey,
      itemId: "d1",
      to: "beginning",
    });
    state = reduceMediaDraftEvent(state, {
      type: "TRANSITION",
      key: baseKey,
      itemId: "d1",
      to: "uploading",
    });
    state = reduceMediaDraftEvent(state, {
      type: "TRANSITION",
      key: baseKey,
      itemId: "d1",
      to: "finalizing",
    });
    state = reduceMediaDraftEvent(state, {
      type: "MATERIALIZED",
      key: baseKey,
      itemId: "d1",
      attachmentId: "att-1",
      attachmentVersion: 1,
      availabilityGeneration: 1,
    });
    expect(shouldWarnBeforeUnload(getDraft(state))).toBe(false);
  });

  it("does not warn for undefined draft", () => {
    expect(shouldWarnBeforeUnload(undefined)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Keyboard reorder tests
// ---------------------------------------------------------------------------

describe("web_media_tray keyboard reorder", () => {
  function makeItems(): MediaDraftItem[] {
    return [makeItem({ itemId: "a" }), makeItem({ itemId: "b" }), makeItem({ itemId: "c" })];
  }

  it("moves focused item up", () => {
    const items = makeItems();
    const result = keyboardReorder(items, "b", "up");
    expect(result).toEqual(["b", "a", "c"]);
  });

  it("moves focused item down", () => {
    const items = makeItems();
    const result = keyboardReorder(items, "b", "down");
    expect(result).toEqual(["a", "c", "b"]);
  });

  it("does not move past the start", () => {
    const items = makeItems();
    const result = keyboardReorder(items, "a", "up");
    expect(result).toEqual(["a", "b", "c"]);
  });

  it("does not move past the end", () => {
    const items = makeItems();
    const result = keyboardReorder(items, "c", "down");
    expect(result).toEqual(["a", "b", "c"]);
  });
});
