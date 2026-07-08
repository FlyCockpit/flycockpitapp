import { randomUUID } from "node:crypto";

import { isAdminRole } from "@flycockpit/auth/roles";
import prisma from "@flycockpit/db";

import {
  deleteStorageObject,
  getStorageObject,
  headStorageObject,
  type PresignedPut,
  presignPut,
  putStorageObject,
  type StorageObject,
  storage,
} from "./storage";

/**
 * The single permission boundary for assets. Both the HTTP asset endpoint
 * (apps/server/src/index.ts) and the image transform endpoint call
 * `fetchAsset()` directly — no internal HTTP self-requests, no duplicated
 * auth logic. The image endpoint inherits visibility from the source so
 * cache headers stay consistent.
 *
 * Permission model (default): an asset is accessible if its visibility is
 * PUBLIC, or the requester is the owner, or the requester is an admin. To
 * customize, override `canViewAsset` below — every read in this codebase
 * goes through it.
 */

export type AssetVisibility = "PUBLIC" | "RESTRICTED";

export type AssetStatus = "PENDING" | "READY";
export type AssetMetadataState = "CLIENT_HINT" | "SERVER_VERIFIED";

export type AssetMeta = {
  id: string;
  storageKey: string;
  mimeType: string;
  size: number;
  visibility: AssetVisibility;
  ownerId: string | null;
  width: number | null;
  height: number | null;
  blurhash: string | null;
  status: AssetStatus;
  metadataState: AssetMetadataState;
};

export type AssetMetadataHint = {
  width?: number | null;
  height?: number | null;
  blurhash?: string | null;
};

export type AssetFetchResult = {
  meta: AssetMeta;
  body: StorageObject;
};

export type Viewer =
  | {
      kind: "anonymous";
    }
  | {
      kind: "user";
      userId: string;
      role: string;
    };

export class AssetError extends Error {
  constructor(
    public code:
      | "NOT_FOUND"
      | "FORBIDDEN"
      | "STORAGE_DISABLED"
      | "GONE"
      | "ALREADY_FINALIZED"
      | "UPLOAD_MISSING"
      | "SIZE_MISMATCH",
    message: string,
  ) {
    super(message);
    this.name = "AssetError";
  }
}

/**
 * Default permission rule: PUBLIC assets are visible to everyone; RESTRICTED
 * assets require the viewer to be the owner or an admin. Override here if
 * the app has more elaborate access rules (org-scoped sharing, ACLs, etc.) —
 * every asset read in the codebase calls this.
 */
export function canViewAsset(asset: AssetMeta, viewer: Viewer): boolean {
  if (asset.visibility === "PUBLIC") return true;
  if (viewer.kind === "anonymous") return false;
  if (isAdminRole(viewer.role)) return true;
  return asset.ownerId !== null && asset.ownerId === viewer.userId;
}

/**
 * Look up an Asset row, check permissions, and stream the bytes from storage.
 * Throws AssetError with a code that maps cleanly to HTTP status.
 *
 * Callers (asset endpoint, image endpoint) decide cache headers based on
 * `meta.visibility`. The single-source-of-truth pattern means flipping an
 * asset from PUBLIC to RESTRICTED is a one-row update and the next request
 * inherits the new policy.
 */
export async function fetchAsset(id: string, viewer: Viewer): Promise<AssetFetchResult> {
  if (!storage) throw new AssetError("STORAGE_DISABLED", "Object storage is not configured");

  const meta = await prisma.asset.findUnique({ where: { id } });
  if (!meta) throw new AssetError("NOT_FOUND", "Asset not found");

  const assetMeta = toAssetMeta(meta);
  if (!canViewAsset(assetMeta, viewer)) {
    // 404 (not 403) on the public-facing endpoint to avoid leaking
    // existence; the HTTP layer translates AssetError("FORBIDDEN") to 404.
    throw new AssetError("FORBIDDEN", "Not allowed to view this asset");
  }

  const body = await getStorageObject(assetMeta.storageKey);
  if (!body) {
    throw new AssetError(
      "GONE",
      `Asset ${id} has a database row but storage object ${assetMeta.storageKey} is missing`,
    );
  }
  return { meta: assetMeta, body };
}

/**
 * Build the cache-control header for an asset response. PUBLIC → 24h shared
 * cache. RESTRICTED → 24h browser cache only (no CDN). Image endpoint reuses
 * this for its own responses so the derivative inherits the source's policy.
 */
export function assetCacheControl(visibility: AssetVisibility): string {
  if (visibility === "PUBLIC") {
    return "public, max-age=86400, immutable";
  }
  return "private, max-age=86400";
}

export type CreateAssetInput = {
  body: Uint8Array;
  mimeType: string;
  visibility: AssetVisibility;
  ownerId: string | null;
  width?: number | null;
  height?: number | null;
  blurhash?: string | null;
};

/**
 * Write the bytes to storage and create an Asset row. The storage key is a
 * v4 UUID — opaque to callers, stable for the lifetime of the row, never
 * collides. Returning the Asset id is sufficient: the HTTP path (and image
 * proxy) take the id and resolve everything else.
 */
export async function createAsset(input: CreateAssetInput): Promise<AssetMeta> {
  if (!storage) throw new AssetError("STORAGE_DISABLED", "Object storage is not configured");

  const storageKey = `assets/${randomUUID()}`;
  await putStorageObject(storageKey, input.body, input.mimeType);

  try {
    const row = await prisma.asset.create({
      data: {
        storageKey,
        mimeType: input.mimeType,
        size: BigInt(input.body.byteLength),
        visibility: input.visibility,
        ownerId: input.ownerId,
        width: input.width ?? null,
        height: input.height ?? null,
        blurhash: input.blurhash ?? null,
        isMetadataVerified: true,
        metadataState: "SERVER_VERIFIED",
      },
    });
    return toAssetMeta(row);
  } catch (err) {
    // Roll back the storage write if the DB row fails — otherwise we leak
    // orphan objects.
    await deleteStorageObject(storageKey).catch(() => {
      // Best-effort cleanup; the original error matters more than the cleanup error.
    });
    throw err;
  }
}

function toAssetMeta(row: {
  id: string;
  storageKey: string;
  mimeType: string;
  size: bigint | number;
  visibility: { toString(): string } | string;
  ownerId: string | null;
  width: number | null;
  height: number | null;
  blurhash: string | null;
  status: { toString(): string } | string;
  isMetadataVerified: boolean;
  metadataState: { toString(): string } | string | null;
}): AssetMeta {
  // Prisma serializes enum fields as objects; coerce to a plain string —
  // see the router enum-serialization policy.
  const visibility = String(row.visibility) as AssetVisibility;
  const status = String(row.status) as AssetStatus;
  const metadataState =
    row.metadataState === null
      ? row.isMetadataVerified
        ? "SERVER_VERIFIED"
        : "CLIENT_HINT"
      : (String(row.metadataState) as AssetMetadataState);
  // size is stored as BigInt to accommodate >2GB files; coerce to number at
  // the boundary so the API surface stays JSON-serializable. Individual asset
  // sizes are bounded by S3 object limits, well below Number.MAX_SAFE_INTEGER.
  return {
    id: row.id,
    storageKey: row.storageKey,
    mimeType: row.mimeType,
    size: Number(row.size),
    visibility,
    ownerId: row.ownerId,
    width: row.width,
    height: row.height,
    blurhash: row.blurhash,
    status,
    metadataState,
  };
}

export type PresignAssetInput = {
  mimeType: string;
  size: number;
  visibility: AssetVisibility;
  ownerId: string | null;
  hint?: AssetMetadataHint;
};

export type PresignAssetResult = {
  assetId: string;
  storageKey: string;
  upload: PresignedPut;
};

/**
 * Issue a presigned PUT URL for direct-to-S3 upload, and create a PENDING
 * Asset row carrying the client-supplied metadata hint. The row exists before
 * the bytes do — `finalizeAsset` flips it to READY once a HEAD confirms the
 * object is in storage. Orphan PENDING rows (client never finalizes) are safe
 * to reap after the presign URL expires.
 */
export async function presignAsset(input: PresignAssetInput): Promise<PresignAssetResult> {
  if (!storage) throw new AssetError("STORAGE_DISABLED", "Object storage is not configured");

  const storageKey = `assets/${randomUUID()}`;
  const upload = await presignPut(storageKey, input.mimeType, input.size);

  const row = await prisma.asset.create({
    data: {
      storageKey,
      mimeType: input.mimeType,
      size: BigInt(input.size),
      visibility: input.visibility,
      ownerId: input.ownerId,
      width: input.hint?.width ?? null,
      height: input.hint?.height ?? null,
      blurhash: input.hint?.blurhash ?? null,
      status: "PENDING",
      // Seed the heartbeat at row creation so the cleanup job's grace window
      // starts from "row exists" rather than "first client heartbeat arrived"
      // — covers the 60s before the client posts its first beat.
      uploadHeartbeatAt: new Date(),
      // Client-supplied hint is provisional by definition. A worker
      // (analyze-asset) flips this after re-deriving from S3 bytes.
      isMetadataVerified: false,
      metadataState: "CLIENT_HINT",
    },
  });

  return { assetId: row.id, storageKey, upload };
}

export type FinalizeAssetInput = {
  assetId: string;
  viewer: Viewer;
};

/**
 * Confirm a presigned upload reached storage and flip the row to READY. HEAD
 * the object (refuse if missing, refuse if size differs from what the client
 * declared at presign time), then update the row. Idempotent on already-READY
 * rows so a retried client call doesn't 500.
 */
export async function finalizeAsset(input: FinalizeAssetInput): Promise<AssetMeta> {
  if (!storage) throw new AssetError("STORAGE_DISABLED", "Object storage is not configured");

  const row = await prisma.asset.findUnique({ where: { id: input.assetId } });
  if (!row) throw new AssetError("NOT_FOUND", "Asset not found");

  const meta = toAssetMeta(row);
  // Only the owner (or an admin) may finalize. Anonymous viewers and other
  // users get a NOT_FOUND so the endpoint cannot be used as a presence
  // oracle for ids issued to a different user.
  if (
    input.viewer.kind === "anonymous" ||
    (!isAdminRole(input.viewer.role) && meta.ownerId !== input.viewer.userId)
  ) {
    throw new AssetError("NOT_FOUND", "Asset not found");
  }

  if (meta.status === "READY") {
    // Idempotent: a retried finalize on a READY row returns the existing
    // meta rather than re-HEADing or erroring.
    return meta;
  }

  const head = await headStorageObject(meta.storageKey);
  if (!head) throw new AssetError("UPLOAD_MISSING", "Storage object is missing");
  if (head.contentLength !== meta.size) {
    throw new AssetError(
      "SIZE_MISMATCH",
      `Stored object size (${head.contentLength}) does not match presigned size (${meta.size})`,
    );
  }

  const updated = await prisma.asset.update({
    where: { id: meta.id },
    data: { status: "READY" },
  });
  return toAssetMeta(updated);
}

export type HeartbeatAssetInput = {
  assetId: string;
  viewer: Viewer;
};

/**
 * Bump `uploadHeartbeatAt` on a PENDING Asset row so the cleanup job knows the
 * client is still working on the upload. Only the owner (or an admin) may
 * heartbeat their own row, and only while it is still PENDING — heartbeating
 * a READY row is a no-op (the client should have stopped). Non-owners get
 * NOT_FOUND so the endpoint isn't a presence oracle.
 */
export async function heartbeatAsset(input: HeartbeatAssetInput): Promise<void> {
  const row = await prisma.asset.findUnique({
    where: { id: input.assetId },
    select: { id: true, ownerId: true, status: true },
  });
  if (!row) throw new AssetError("NOT_FOUND", "Asset not found");

  const status = String(row.status) as AssetStatus;
  if (
    input.viewer.kind === "anonymous" ||
    (!isAdminRole(input.viewer.role) && row.ownerId !== input.viewer.userId)
  ) {
    throw new AssetError("NOT_FOUND", "Asset not found");
  }
  if (status !== "PENDING") return;

  await prisma.asset.update({
    where: { id: row.id },
    data: { uploadHeartbeatAt: new Date() },
  });
}

export type AssetMetadataPatch = {
  width?: number | null;
  height?: number | null;
  blurhash?: string | null;
  mimeType?: string;
  size?: number;
  metadataState?: AssetMetadataState;
};

/**
 * Overwrite metadata columns with values derived server-side. Used by the
 * analyze-asset worker after it downloads the bytes from S3 and runs sharp.
 * The metadata state should flip to SERVER_VERIFIED here — that's the whole
 * reason this function exists.
 */
export async function updateAssetMetadata(
  assetId: string,
  patch: AssetMetadataPatch,
): Promise<AssetMeta> {
  const updated = await prisma.asset.update({
    where: { id: assetId },
    data: {
      width: patch.width ?? undefined,
      height: patch.height ?? undefined,
      blurhash: patch.blurhash ?? undefined,
      mimeType: patch.mimeType ?? undefined,
      size: patch.size !== undefined ? BigInt(patch.size) : undefined,
      isMetadataVerified:
        patch.metadataState === undefined ? undefined : patch.metadataState === "SERVER_VERIFIED",
      metadataState: patch.metadataState ?? undefined,
    },
  });
  return toAssetMeta(updated);
}

/**
 * Worker entry point for the analyze-asset job. Loads the row, downloads the
 * bytes from S3, runs sharp/blurhash analysis, and overwrites the hint columns
 * with verified values. No-op for non-image assets and for rows still in
 * PENDING (the upload didn't complete yet — the job will be retried by BullMQ
 * if it landed before the finalize call).
 */
export async function analyzeStoredAsset(assetId: string): Promise<AssetMeta | null> {
  // Lazy-import sharp/blurhash so callers that only need the read/write path
  // (presign, finalize, fetch) don't pull native deps into their bundle.
  const { analyzeImage } = await import("./images");

  const row = await prisma.asset.findUnique({ where: { id: assetId } });
  if (!row) return null;
  const meta = toAssetMeta(row);
  if (meta.status !== "READY") return null;
  if (!meta.mimeType.startsWith("image/")) {
    // Nothing to derive for non-image assets; mark server-verified so the
    // column reflects the truth ("we looked, there's nothing to add").
    return updateAssetMetadata(meta.id, { metadataState: "SERVER_VERIFIED" });
  }

  const body = await getStorageObject(meta.storageKey);
  if (!body) return null;
  const analysis = await analyzeImage(body.body, meta.mimeType);
  if (!analysis) {
    // Sharp couldn't parse the file. Leave the hint in place; mark
    // server-verified so we don't keep retrying — the client claim is the
    // best we have.
    return updateAssetMetadata(meta.id, { metadataState: "SERVER_VERIFIED" });
  }
  return updateAssetMetadata(meta.id, {
    width: analysis.width,
    height: analysis.height,
    blurhash: analysis.blurhash,
    metadataState: "SERVER_VERIFIED",
  });
}
