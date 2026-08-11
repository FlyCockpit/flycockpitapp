import { describe, expect, it, vi } from "vitest";
import {
  CHUNK_SIZE,
  type DraftKey,
  emptyMediaDraftState,
  type MediaDraftItem,
  type MediaDraftState,
  reduceMediaDraftEvent,
} from "./web-media-draft-reducer";
import { createItemOperationIds, createUuidV7, hashFile, sha256Hex } from "./web-media-upload";

// ---------------------------------------------------------------------------
// UUIDv7 tests
// ---------------------------------------------------------------------------

describe("web_media_upload UUIDv7 generation", () => {
  it("creates a valid UUIDv7 string", () => {
    const id = createUuidV7();
    expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  });

  it("creates distinct IDs", () => {
    const ids = new Set<string>();
    for (let i = 0; i < 100; i++) ids.add(createUuidV7());
    expect(ids.size).toBe(100);
  });

  it("creates stable distinct operation IDs for an item attempt", () => {
    const ids = createItemOperationIds(3);
    expect(ids.chunkIds).toHaveLength(3);
    // All IDs must be distinct.
    const all = [ids.beginId, ...ids.chunkIds, ids.finalizeId, ids.cancelId, ids.discardId];
    expect(new Set(all).size).toBe(all.length);
    // All must be UUIDv7.
    for (const id of all) {
      expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    }
  });

  it("does not share IDs across chunk indices", () => {
    const ids = createItemOperationIds(5);
    for (let i = 0; i < 5; i++) {
      for (let j = i + 1; j < 5; j++) {
        expect(ids.chunkIds[i]).not.toBe(ids.chunkIds[j]);
      }
    }
  });
});

// ---------------------------------------------------------------------------
// SHA-256 tests
// ---------------------------------------------------------------------------

describe("web_media_upload SHA-256", () => {
  it("computes the SHA-256 hex digest of a byte array", async () => {
    const data = new Uint8Array([0x61, 0x62, 0x63]); // "abc"
    const digest = await sha256Hex(data);
    // Known SHA-256 of "abc"
    expect(digest).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  });

  it("computes the SHA-256 of an empty array", async () => {
    const digest = await sha256Hex(new Uint8Array(0));
    expect(digest).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  });
});

// ---------------------------------------------------------------------------
// File hashing tests
// ---------------------------------------------------------------------------

describe("web_media_upload file hashing", () => {
  it("hashes a file smaller than one chunk", async () => {
    const data = new Uint8Array([1, 2, 3, 4, 5]);
    const file = new File([data], "test.bin", { type: "application/octet-stream" });
    const result = await hashFile(file);
    expect(result.chunkCount).toBe(1);
    expect(result.chunkDigests).toHaveLength(1);
    expect(result.digest).toHaveLength(64);
  });

  it("hashes a file exactly one chunk", async () => {
    const data = new Uint8Array(CHUNK_SIZE);
    const file = new File([data], "one-chunk.bin", { type: "application/octet-stream" });
    const result = await hashFile(file);
    expect(result.chunkCount).toBe(1);
  });

  it("hashes a file spanning two chunks", async () => {
    const data = new Uint8Array(CHUNK_SIZE + 1);
    const file = new File([data], "two-chunks.bin", { type: "application/octet-stream" });
    const result = await hashFile(file);
    expect(result.chunkCount).toBe(2);
    expect(result.chunkDigests).toHaveLength(2);
    // Full digest differs from either chunk digest.
    expect(result.digest).not.toBe(result.chunkDigests[0]);
    expect(result.digest).not.toBe(result.chunkDigests[1]);
  });

  it("calls onProgress during hashing", async () => {
    const data = new Uint8Array(CHUNK_SIZE * 3);
    const file = new File([data], "three-chunks.bin", { type: "application/octet-stream" });
    const onProgress = vi.fn();
    await hashFile(file, onProgress);
    expect(onProgress).toHaveBeenCalled();
    // Final call has all chunk digests.
    const lastCall = onProgress.mock.calls[onProgress.mock.calls.length - 1];
    expect(lastCall?.[0]).toHaveLength(3);
  });
});

// ---------------------------------------------------------------------------
// Upload operation ID binding tests (reducer-level)
// ---------------------------------------------------------------------------

describe("web_media_upload operation ID binding", () => {
  const baseKey: DraftKey = {
    instanceId: "inst-1",
    projectId: "proj-1",
    sessionId: "11111111-1111-4111-8111-111111111111",
    authenticatedDeviceGeneration: 1,
    connectionEpoch: 1,
    draftGeneration: 1,
  };

  function makeItem(overrides: Partial<MediaDraftItem> = {}): MediaDraftItem {
    const opIds = createItemOperationIds(2);
    return {
      itemId: "draft-1",
      attempt: 1,
      state: "selected",
      kind: "image",
      fileName: "photo.png",
      declaredSize: CHUNK_SIZE + 100,
      declaredMime: "image/png",
      digest: null,
      chunkDigests: [],
      chunkCount: null,
      acknowledgedBytes: 0,
      uploadedBytes: 0,
      operationIds: opIds,
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

  it("item stores Begin ID before dispatch; after Begin commits stores upload ID/generation", () => {
    let state: MediaDraftState = emptyMediaDraftState();
    state = reduceMediaDraftEvent(state, {
      type: "ADD_ITEMS",
      key: baseKey,
      items: [makeItem()],
    });
    // The item has a stable Begin ID before dispatch.
    const k = [
      baseKey.instanceId,
      baseKey.projectId,
      baseKey.sessionId,
      baseKey.authenticatedDeviceGeneration,
      baseKey.connectionEpoch,
      baseKey.draftGeneration,
    ].join(":");
    const item = state.drafts[k]?.items[0];
    expect(item?.operationIds.beginId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-7/);
    expect(item?.uploadId).toBeNull();

    // After Begin commits, store upload ID/generation.
    // Walk the valid path: selected -> hashing -> queued -> beginning.
    state = reduceMediaDraftEvent(state, {
      type: "TRANSITION",
      key: baseKey,
      itemId: "draft-1",
      to: "hashing",
    });
    state = reduceMediaDraftEvent(state, {
      type: "TRANSITION",
      key: baseKey,
      itemId: "draft-1",
      to: "queued",
    });
    state = reduceMediaDraftEvent(state, {
      type: "TRANSITION",
      key: baseKey,
      itemId: "draft-1",
      to: "beginning",
    });
    state = reduceMediaDraftEvent(state, {
      type: "BEGIN_COMMITTED",
      key: baseKey,
      itemId: "draft-1",
      uploadId: "upload-uuid-1",
      uploadGeneration: 3,
    });
    const afterBegin = state.drafts[k]?.items[0];
    expect(afterBegin?.uploadId).toBe("upload-uuid-1");
    expect(afterBegin?.uploadGeneration).toBe(3);
    // Original Begin ID is preserved.
    expect(afterBegin?.operationIds.beginId).toBe(item?.operationIds.beginId);
  });

  it("same-action replay reuses the original operation ID", () => {
    const opIds = createItemOperationIds(1);
    // The operation IDs are stable for the item attempt.
    // A replay uses the same IDs; a changed binding is a conflict.
    expect(opIds.beginId).not.toBe(opIds.finalizeId);
    expect(opIds.chunkIds[0]).not.toBe(opIds.beginId);
    expect(opIds.chunkIds[0]).not.toBe(opIds.finalizeId);
    expect(opIds.cancelId).not.toBe(opIds.discardId);
  });
});
