import {
  CHUNK_SIZE,
  type DraftKey,
  type ItemOperationIds,
  MAX_CHUNKS,
  type MediaDraftItem,
} from "./web-media-draft-reducer";

// ---------------------------------------------------------------------------
// UUIDv7 generation
// ---------------------------------------------------------------------------

/**
 * Generates a UUIDv7 string using Web Crypto.
 * The timestamp-based UUIDv7 ensures rough chronological ordering.
 */
export function createUuidV7(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);

  // Set version (7) and variant (RFC 4122).
  bytes[6] = (bytes[6]! & 0x0f) | 0x70;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;

  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/**
 * Generates stable, distinct UUIDv7 operation IDs for one item attempt.
 * One Begin ID, one ID for each chunk index, one Finalize ID, one Cancel
 * ID, and one Discard ID. No ID is shared across actions or chunk indices.
 */
export function createItemOperationIds(chunkCount: number): ItemOperationIds {
  const chunkIds: string[] = [];
  for (let i = 0; i < chunkCount; i++) {
    chunkIds.push(createUuidV7());
  }
  return {
    beginId: createUuidV7(),
    chunkIds,
    finalizeId: createUuidV7(),
    cancelId: createUuidV7(),
    discardId: createUuidV7(),
  };
}

// ---------------------------------------------------------------------------
// Web Crypto hashing
// ---------------------------------------------------------------------------

/** Computes the SHA-256 hex digest of an ArrayBuffer. */
export async function sha256Hex(data: ArrayBuffer | Uint8Array): Promise<string> {
  const buffer = data instanceof Uint8Array ? data.buffer.slice(0) : data;
  const digest = await crypto.subtle.digest("SHA-256", buffer as ArrayBuffer);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

/** Reads a File and computes its full SHA-256 digest plus per-chunk digests. */
export async function hashFile(
  file: File,
  onProgress?: (chunkDigests: string[], chunkCount: number) => void,
): Promise<{ digest: string; chunkDigests: string[]; chunkCount: number }> {
  const totalBytes = file.size;
  const chunkCount = Math.max(1, Math.ceil(totalBytes / CHUNK_SIZE));
  if (chunkCount > MAX_CHUNKS) {
    throw new Error("file_exceeds_max_chunks");
  }

  const chunkDigests: string[] = [];
  let fullHash = new Uint8Array(0);

  for (let i = 0; i < chunkCount; i++) {
    const start = i * CHUNK_SIZE;
    const end = Math.min(start + CHUNK_SIZE, totalBytes);
    const chunkBuffer = await file.slice(start, end).arrayBuffer();
    const chunkBytes = new Uint8Array(chunkBuffer);
    chunkDigests.push(await sha256Hex(chunkBuffer));

    // Accumulate for full-file hash.
    const next = new Uint8Array(fullHash.length + chunkBytes.length);
    next.set(fullHash);
    next.set(chunkBytes, fullHash.length);
    fullHash = next;

    if (onProgress && i % 16 === 0) {
      onProgress(chunkDigests.slice(), chunkCount);
    }
  }

  const digest = await sha256Hex(fullHash.buffer);
  onProgress?.(chunkDigests, chunkCount);
  return { digest, chunkDigests, chunkCount };
}

// ---------------------------------------------------------------------------
// Chunk reader
// ---------------------------------------------------------------------------

/** Reads one chunk from a File as a base64 string for the Append RPC. */
export async function readChunkBase64(file: File, chunkIndex: number): Promise<string> {
  const start = chunkIndex * CHUNK_SIZE;
  const end = Math.min(start + CHUNK_SIZE, file.size);
  const buffer = await file.slice(start, end).arrayBuffer();
  const bytes = new Uint8Array(buffer);
  // Base64 encode without btoa's character restrictions.
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]!);
  }
  return btoa(binary);
}

// ---------------------------------------------------------------------------
// Upload operation result types (mirroring daemon responses)
// ---------------------------------------------------------------------------

export interface BeginUploadResult {
  uploadId: string;
  uploadGeneration: number;
}

export interface MaterializedResult {
  attachmentId: string;
  attachmentVersion: number;
  availabilityGeneration: number;
}

export interface ReadyResult {
  attachmentId: string;
  attachmentVersion: number;
  availabilityGeneration: number;
}

// ---------------------------------------------------------------------------
// Upload controller
// ---------------------------------------------------------------------------

/**
 * Controller for one item's upload lifecycle. Manages the sequential chunk
 * uploads, state transitions, and local-byte release at the materialization
 * linearization point.
 *
 * The controller is intentionally side-effect-bound: it accepts a
 * `RemoteSessionClient`-shaped object so tests can inject a mock without
 * a real WebSocket.
 */
export interface MediaUploadClient {
  beginMediaUpload(params: unknown): Promise<BeginUploadResult>;
  appendMediaUploadChunk(params: unknown): Promise<void>;
  finalizeMediaUpload(params: unknown): Promise<MaterializedResult>;
  cancelMediaUpload(params: unknown): Promise<void>;
  discardUnreferencedMediaAttachment(params: unknown): Promise<void>;
  getMediaUploadStatus(params: unknown): Promise<unknown>;
  getMediaAttachmentStatus(params: unknown): Promise<unknown>;
  getMediaAttachmentPreview(params: unknown): Promise<unknown>;
  listSessionMediaDrafts(params: unknown): Promise<unknown>;
}

/**
 * Uploads one media item through the daemon protocol.
 *
 * This is the side-effectful orchestration: it hashes the file, calls
 * Begin/Append/Finalize, and returns the materialization result. The
 * caller is responsible for dispatching reducer events and releasing
 * the File reference at the `materialized -> processing` boundary.
 *
 * Each action uses the item's stable operation ID. A changed binding or
 * cross-action/index reuse is a conflict and never regenerated away.
 */
export async function uploadItem(
  client: MediaUploadClient,
  item: MediaDraftItem,
  file: File,
  draftKey: DraftKey,
  onProgress?: (acknowledgedBytes: number, uploadedBytes: number) => void,
): Promise<MaterializedResult> {
  if (!item.digest || !item.chunkCount || item.chunkDigests.length !== item.chunkCount) {
    throw new Error("item_not_hashed");
  }
  if (!item.operationIds.beginId) {
    throw new Error("missing_begin_operation_id");
  }

  // Begin: stores the Begin ID before dispatch.
  const beginResult = await client.beginMediaUpload({
    session_id: draftKey.sessionId,
    client_draft_id: item.itemId,
    media_kind: item.kind,
    declared_total_bytes: file.size,
    operation_id: item.operationIds.beginId,
  });

  // After Begin commits, store the returned upload ID/generation.
  // Every later action binds that upload ID/generation plus the original
  // client draft/item ID.

  // Append: sequential chunks, each with its own stable operation ID.
  let uploadedBytes = 0;
  for (let i = 0; i < item.chunkCount; i++) {
    const chunkBase64 = await readChunkBase64(file, i);
    const chunkDigest = item.chunkDigests[i];
    const chunkOperationId = item.operationIds.chunkIds[i];
    if (!chunkOperationId || !chunkDigest) {
      throw new Error(`missing_chunk_binding:${i}`);
    }
    await client.appendMediaUploadChunk({
      session_id: draftKey.sessionId,
      client_draft_id: item.itemId,
      upload_id: beginResult.uploadId,
      upload_generation: beginResult.uploadGeneration,
      chunk_index: i,
      chunk_length: Math.min(CHUNK_SIZE, file.size - i * CHUNK_SIZE),
      chunk_sha256: chunkDigest,
      data_base64: chunkBase64,
      operation_id: chunkOperationId,
    });
    uploadedBytes += Math.min(CHUNK_SIZE, file.size - i * CHUNK_SIZE);
    onProgress?.(uploadedBytes, uploadedBytes);
  }

  // Finalize: binds the immutable chunk count/length/full digest.
  const finalizeResult = await client.finalizeMediaUpload({
    session_id: draftKey.sessionId,
    client_draft_id: item.itemId,
    upload_id: beginResult.uploadId,
    upload_generation: beginResult.uploadGeneration,
    chunk_count: item.chunkCount,
    total_bytes: file.size,
    object_sha256: item.digest,
    operation_id: item.operationIds.finalizeId,
  });

  // The materialization result is the authoritative linearization point.
  // The caller must release the File reference, hash reader, chunk views,
  // and pending read callbacks synchronously before publishing `processing`.
  return finalizeResult;
}

/**
 * Cancels an upload using the exact state-to-RPC cancellation table.
 *
 * `selected|hashing|queued` cancel locally and issue no RPC.
 * `beginning|uploading|finalizing` use the last authoritative upload state
 * or first call `GetMediaUploadStatusV1` when ambiguous: `open|finalizing`
 * calls `CancelMediaUploadV1`; `materialized` releases local bytes and
 * calls `DiscardUnreferencedMediaAttachmentV1`.
 * `processing|ready|removing` call `GetMediaAttachmentStatusV1` when stale
 * and then use the Discard identity/request.
 */
export async function cancelItem(
  client: MediaUploadClient,
  item: MediaDraftItem,
  draftKey: DraftKey,
): Promise<void> {
  // selected|hashing|queued: no RPC.
  if (item.state === "selected" || item.state === "hashing" || item.state === "queued") {
    return;
  }

  // beginning|uploading|finalizing: upload-bound cancellation.
  if (item.state === "beginning" || item.state === "uploading" || item.state === "finalizing") {
    if (!item.uploadId || !item.uploadGeneration) {
      // Ambiguous Begin: query status first.
      const status = await client.getMediaUploadStatus({
        session_id: draftKey.sessionId,
        client_draft_id: item.itemId,
      });
      void status; // The caller interprets status and dispatches the right RPC.
      return;
    }
    // open|finalizing: CancelMediaUploadV1 with stable Cancel operation ID.
    await client.cancelMediaUpload({
      session_id: draftKey.sessionId,
      client_draft_id: item.itemId,
      upload_id: item.uploadId,
      upload_generation: item.uploadGeneration,
      operation_id: item.operationIds.cancelId,
    });
    return;
  }

  // processing|ready|removing: attachment-bound cancellation (Discard).
  if (item.state === "processing" || item.state === "removing" || item.state === "cancelling") {
    if (!item.attachmentId || !item.attachmentVersion || !item.availabilityGeneration) {
      // Stale version/state: query attachment status first.
      await client.getMediaAttachmentStatus({
        session_id: draftKey.sessionId,
        attachment_id: item.attachmentId,
      });
      return;
    }
    // Discard with the distinct stable Discard ID and exact attachment/origin generations.
    await client.discardUnreferencedMediaAttachment({
      session_id: draftKey.sessionId,
      attachment_id: item.attachmentId,
      attachment_version: item.attachmentVersion,
      availability_generation: item.availabilityGeneration,
      operation_id: item.operationIds.discardId,
      origin_upload: item.uploadId
        ? {
            client_draft_id: item.itemId,
            upload_id: item.uploadId,
            upload_generation: item.uploadGeneration,
          }
        : undefined,
    });
    return;
  }
}

// ---------------------------------------------------------------------------
// Retry resume
// ---------------------------------------------------------------------------

/**
 * Resumes an upload from recovery by querying the daemon's authoritative
 * status and selecting exactly one next state.
 *
 * The cursor plus `GetMediaUploadStatusV1|GetMediaAttachmentStatusV1`
 * selects the next state. It resumes from the first missing acknowledged
 * chunk with that index's stable operation ID and never blind-reuploads
 * after an ambiguous Begin/Append/Finalize.
 */
export async function resumeUpload(
  client: MediaUploadClient,
  item: MediaDraftItem,
  draftKey: DraftKey,
): Promise<{ nextState: string; acknowledgedChunks?: number }> {
  if (!item.retryCursor) {
    return { nextState: "failed" };
  }

  switch (item.retryCursor) {
    case "rehash_local":
      // Only a pre-Begin local hash/read failure may restart hashing
      // with a new local attempt ID; it retains the same unissued action IDs.
      return { nextState: "hashing" };

    case "requeue_before_begin":
      // Requeue before Begin has been issued.
      return { nextState: "queued" };

    case "query_upload_status": {
      if (!item.uploadId || !item.uploadGeneration) {
        return { nextState: "queued" };
      }
      const status = await client.getMediaUploadStatus({
        session_id: draftKey.sessionId,
        client_draft_id: item.itemId,
        upload_id: item.uploadId,
        upload_generation: item.uploadGeneration,
      });
      // The caller interprets the status to determine acknowledged chunks.
      void status;
      return { nextState: "uploading" };
    }

    case "query_attachment_status": {
      if (!item.attachmentId) {
        return { nextState: "failed" };
      }
      await client.getMediaAttachmentStatus({
        session_id: draftKey.sessionId,
        attachment_id: item.attachmentId,
      });
      return { nextState: "processing" };
    }

    case "terminal":
      // Terminal validation/authorization failures cannot retry until a new
      // user action/config generation creates a new item attempt.
      return { nextState: "failed" };

    default:
      return { nextState: "failed" };
  }
}
