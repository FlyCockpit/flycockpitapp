import { Readable } from "node:stream";
import type { ReadableStream as NodeReadableStream } from "node:stream/web";
import {
  AbortMultipartUploadCommand,
  CompleteMultipartUploadCommand,
  CreateMultipartUploadCommand,
  DeleteObjectCommand,
  GetObjectCommand,
  HeadObjectCommand,
  ListMultipartUploadsCommand,
  ListObjectsV2Command,
  PutObjectCommand,
  S3Client,
  UploadPartCommand,
} from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { env, S3_FORCE_PATH_STYLE } from "@flycockpit/env/shared";

/**
 * S3-compatible object storage client. Provider-agnostic: works with AWS S3,
 * Cloudflare R2, Backblaze B2, MinIO, DigitalOcean Spaces, etc. The choice
 * of backend is encoded entirely in env vars — see packages/env/src/server.ts
 * (S3_ENDPOINT, S3_REGION, S3_FORCE_PATH_STYLE).
 *
 * Storage is **opt-in**: if S3_BUCKET is unset, `storage` is null and the
 * asset/image endpoints surface a 503. The rest of the app boots fine.
 *
 * S3_BUCKET accepts either a plain bucket name (`my-bucket`) or a
 * `bucket/key/prefix` form (`shared-bucket/app-a`). When a `/` is present,
 * everything before the first slash is the bucket and the remainder is a key
 * prefix transparently prepended to every stored object. S3 bucket names can
 * never contain `/`, so the delimiter is unambiguous. A plain name yields an
 * empty prefix and is byte-for-byte identical to the no-prefix behaviour.
 * The prefix is purely a storage-access concern: `Asset.storageKey` (and the
 * keys the cleanup sweep compares) stay logical (`assets/<uuid>`) — the prefix
 * is added on the way into S3 and stripped on the way back out of LIST.
 */

export type Storage = {
  bucket: string;
  client: S3Client;
  /** Normalised key prefix: "" or "<prefix>/" (trailing slash, no leading). */
  keyPrefix: string;
};

/**
 * Split a raw `S3_BUCKET` value into its bucket and normalised key prefix.
 * Pure (no env, no S3) so it is unit-testable in isolation — cleanup safety
 * depends on this round-tripping exactly with {@link stripKeyPrefix}.
 *
 *   "my-bucket"          → { bucket: "my-bucket",  keyPrefix: ""        }
 *   "shared/app-a"       → { bucket: "shared",     keyPrefix: "app-a/"  }
 *   "shared/team/app-a"  → { bucket: "shared",     keyPrefix: "team/app-a/" }
 *   "shared//app-a//"    → { bucket: "shared",     keyPrefix: "app-a/"  }
 *   "bucket/"            → { bucket: "bucket",     keyPrefix: ""        }
 */
export function parseBucketSpec(raw: string): { bucket: string; keyPrefix: string } {
  const slash = raw.indexOf("/");
  const bucket = slash === -1 ? raw : raw.slice(0, slash);
  // Collapse any leading/trailing slashes in the prefix segment, then re-add a
  // single trailing slash so `keyPrefix + key` needs no separator logic.
  const rawPrefix = slash === -1 ? "" : raw.slice(slash + 1).replace(/^\/+|\/+$/g, "");
  return { bucket, keyPrefix: rawPrefix ? `${rawPrefix}/` : "" };
}

/**
 * Map a logical key (what callers and the DB use, e.g. `assets/<uuid>`) to the
 * physical S3 key (`<keyPrefix>assets/<uuid>`). Identity when no prefix. Pure.
 */
export function applyKeyPrefix(keyPrefix: string, key: string): string {
  return keyPrefix + key;
}

/**
 * Inverse of {@link applyKeyPrefix}: strip the prefix off a key S3 handed back
 * (LIST results) so callers and the cleanup sweep keep comparing logical keys
 * against `Asset.storageKey`. Defensive `startsWith` guard — an unprefixed key
 * (shouldn't happen under a configured prefix) passes through unchanged. Pure.
 */
export function stripKeyPrefix(keyPrefix: string, key: string): string {
  return keyPrefix && key.startsWith(keyPrefix) ? key.slice(keyPrefix.length) : key;
}

function buildStorage(): Storage | null {
  if (!env.S3_BUCKET) return null;
  if (!env.S3_ACCESS_KEY_ID || !env.S3_SECRET_ACCESS_KEY) {
    console.warn(
      "[storage] S3_BUCKET is set but S3_ACCESS_KEY_ID / S3_SECRET_ACCESS_KEY are missing — disabling asset endpoints.",
    );
    return null;
  }
  const { bucket, keyPrefix } = parseBucketSpec(env.S3_BUCKET);
  const client = new S3Client({
    region: env.S3_REGION,
    endpoint: env.S3_ENDPOINT,
    forcePathStyle: S3_FORCE_PATH_STYLE,
    credentials: {
      accessKeyId: env.S3_ACCESS_KEY_ID,
      secretAccessKey: env.S3_SECRET_ACCESS_KEY,
    },
  });
  return { bucket, client, keyPrefix };
}

export const storage: Storage | null = buildStorage();

/** Thin {@link Storage}-bound wrappers over the pure key helpers above. */
function physicalKey(s: Storage, key: string): string {
  return applyKeyPrefix(s.keyPrefix, key);
}

function logicalKey(s: Storage, key: string): string {
  return stripKeyPrefix(s.keyPrefix, key);
}

export type StorageObject = {
  body: Uint8Array;
  contentType: string;
  contentLength: number;
};

export type StorageObjectStream = {
  body: NodeJS.ReadableStream;
  contentType: string;
  contentLength: number | null;
};

/**
 * Fetch an object's bytes + content type from object storage. Returns null if
 * the object doesn't exist. Throws on any other transport error.
 */
export async function getStorageObject(key: string): Promise<StorageObject | null> {
  if (!storage) throw new Error("Storage is not configured");
  try {
    const result = await storage.client.send(
      new GetObjectCommand({ Bucket: storage.bucket, Key: physicalKey(storage, key) }),
    );
    if (!result.Body) return null;
    const body = await result.Body.transformToByteArray();
    return {
      body,
      contentType: result.ContentType ?? "application/octet-stream",
      contentLength: result.ContentLength ?? body.byteLength,
    };
  } catch (err: unknown) {
    if (isNotFoundError(err)) return null;
    throw err;
  }
}

/**
 * Fetch an object's body as a stream. Use this for video-sized objects; the
 * byte-array helpers intentionally buffer and are only appropriate for small
 * assets or HLS segments.
 */
export async function getStorageObjectStream(key: string): Promise<StorageObjectStream | null> {
  if (!storage) throw new Error("Storage is not configured");
  try {
    const result = await storage.client.send(
      new GetObjectCommand({ Bucket: storage.bucket, Key: physicalKey(storage, key) }),
    );
    if (!result.Body) return null;
    return {
      body: toNodeReadable(result.Body),
      contentType: result.ContentType ?? "application/octet-stream",
      contentLength: result.ContentLength ?? null,
    };
  } catch (err: unknown) {
    if (isNotFoundError(err)) return null;
    throw err;
  }
}

export async function putStorageObject(
  key: string,
  body: Uint8Array | Buffer,
  contentType: string,
): Promise<void> {
  if (!storage) throw new Error("Storage is not configured");
  await storage.client.send(
    new PutObjectCommand({
      Bucket: storage.bucket,
      Key: physicalKey(storage, key),
      Body: body,
      ContentType: contentType,
    }),
  );
}

export async function deleteStorageObject(key: string): Promise<void> {
  if (!storage) throw new Error("Storage is not configured");
  await storage.client.send(
    new DeleteObjectCommand({ Bucket: storage.bucket, Key: physicalKey(storage, key) }),
  );
}

const PRESIGN_EXPIRES_SECONDS = 300;

export type PresignedPut = {
  url: string;
  headers: Record<string, string>;
  expiresIn: number;
};

/**
 * Generate a short-lived presigned PUT URL for direct-to-S3 uploads. The
 * Content-Type and Content-Length are baked into the signature, so S3 rejects
 * the PUT if the client lies about either. Used by the presigned upload flow
 * (asset-routes.ts → /api/assets/presign) to keep bytes off the app server.
 */
export async function presignPut(
  key: string,
  contentType: string,
  contentLength: number,
): Promise<PresignedPut> {
  if (!storage) throw new Error("Storage is not configured");
  const url = await getSignedUrl(
    storage.client,
    new PutObjectCommand({
      Bucket: storage.bucket,
      Key: physicalKey(storage, key),
      ContentType: contentType,
      ContentLength: contentLength,
    }),
    { expiresIn: PRESIGN_EXPIRES_SECONDS },
  );
  return {
    url,
    headers: {
      "Content-Type": contentType,
      "Content-Length": String(contentLength),
    },
    expiresIn: PRESIGN_EXPIRES_SECONDS,
  };
}

export async function presignGet(
  key: string,
  filename?: string,
): Promise<{ url: string; expiresIn: number }> {
  if (!storage) throw new Error("Storage is not configured");
  const url = await getSignedUrl(
    storage.client,
    new GetObjectCommand({
      Bucket: storage.bucket,
      Key: physicalKey(storage, key),
      ...(filename
        ? {
            ResponseContentDisposition: 'attachment; filename="' + filename.replace(/"/g, "") + '"',
          }
        : {}),
    }),
    { expiresIn: PRESIGN_EXPIRES_SECONDS },
  );
  return { url, expiresIn: PRESIGN_EXPIRES_SECONDS };
}

export type StorageObjectHead = {
  contentLength: number;
  contentType: string;
};

/**
 * HEAD an object to confirm presence and read its content length / type.
 * Returns null if the object does not exist. Used by the finalize handler to
 * verify a presigned upload actually deposited bytes before flipping the row
 * to READY.
 */
export async function headStorageObject(key: string): Promise<StorageObjectHead | null> {
  if (!storage) throw new Error("Storage is not configured");
  try {
    const result = await storage.client.send(
      new HeadObjectCommand({ Bucket: storage.bucket, Key: physicalKey(storage, key) }),
    );
    return {
      contentLength: result.ContentLength ?? 0,
      contentType: result.ContentType ?? "application/octet-stream",
    };
  } catch (err: unknown) {
    if (isNotFoundError(err)) return null;
    throw err;
  }
}

export type StorageObjectListEntry = {
  key: string;
  size: number;
  lastModified: Date | null;
};

/**
 * Iterate every object under a key prefix. Pages through `ListObjectsV2`
 * (1000 entries per call) so the caller can stream rather than buffer the
 * whole bucket — important for the cleanup job, which needs to LIST every
 * `assets/` key but never hold all of them in memory at once.
 */
export async function* listStorageObjects(prefix: string): AsyncGenerator<StorageObjectListEntry> {
  if (!storage) throw new Error("Storage is not configured");
  let continuationToken: string | undefined;
  do {
    const result = await storage.client.send(
      new ListObjectsV2Command({
        Bucket: storage.bucket,
        Prefix: physicalKey(storage, prefix),
        ContinuationToken: continuationToken,
      }),
    );
    for (const obj of result.Contents ?? []) {
      if (!obj.Key) continue;
      yield {
        key: logicalKey(storage, obj.Key),
        size: obj.Size ?? 0,
        lastModified: obj.LastModified ?? null,
      };
    }
    continuationToken = result.IsTruncated ? result.NextContinuationToken : undefined;
  } while (continuationToken);
}

export type IncompleteMultipartUpload = {
  key: string;
  uploadId: string;
  initiated: Date | null;
};

/**
 * Iterate incomplete multipart uploads under a key prefix. These don't show
 * up in `ListObjectsV2` and quietly accrue storage charges until aborted.
 * Flycockpit does not use multipart uploads, so this is expected to return
 * nothing — keep the sweep anyway for defense against future code paths or
 * external tools that initiate multiparts against the same bucket.
 */
export async function* listIncompleteMultipartUploads(
  prefix: string,
): AsyncGenerator<IncompleteMultipartUpload> {
  if (!storage) throw new Error("Storage is not configured");
  let keyMarker: string | undefined;
  let uploadIdMarker: string | undefined;
  do {
    const result = await storage.client.send(
      new ListMultipartUploadsCommand({
        Bucket: storage.bucket,
        Prefix: physicalKey(storage, prefix),
        KeyMarker: keyMarker,
        UploadIdMarker: uploadIdMarker,
      }),
    );
    for (const upload of result.Uploads ?? []) {
      if (!upload.Key || !upload.UploadId) continue;
      yield {
        key: logicalKey(storage, upload.Key),
        uploadId: upload.UploadId,
        initiated: upload.Initiated ?? null,
      };
    }
    if (result.IsTruncated) {
      keyMarker = result.NextKeyMarker;
      uploadIdMarker = result.NextUploadIdMarker;
    } else {
      keyMarker = undefined;
      uploadIdMarker = undefined;
    }
  } while (keyMarker || uploadIdMarker);
}

export async function abortMultipartUpload(key: string, uploadId: string): Promise<void> {
  if (!storage) throw new Error("Storage is not configured");
  await storage.client.send(
    new AbortMultipartUploadCommand({
      Bucket: storage.bucket,
      Key: physicalKey(storage, key),
      UploadId: uploadId,
    }),
  );
}

// ---------------------------------------------------------------------------
// Multipart upload — for large objects (video sources, anything > 100MB).
// ---------------------------------------------------------------------------

/**
 * Initiate a multipart upload. Returns the UploadId the client must pass back
 * with every part. The presign flow for each part is `presignUploadPart`
 * below; on completion `completeMultipartUpload` finalizes the object.
 *
 * The single-PUT presign at `presignPut` is fine up to ~5 GB but uses one
 * signed URL — a flaky network kills the entire upload. Multipart lets a
 * client retry an individual part, so it's the right call for video sources
 * (typically 100MB – 50GB).
 */
export async function createMultipartUpload(
  key: string,
  contentType: string,
): Promise<{ uploadId: string }> {
  if (!storage) throw new Error("Storage is not configured");
  const result = await storage.client.send(
    new CreateMultipartUploadCommand({
      Bucket: storage.bucket,
      Key: physicalKey(storage, key),
      ContentType: contentType,
    }),
  );
  if (!result.UploadId) {
    throw new Error("S3 did not return an UploadId");
  }
  return { uploadId: result.UploadId };
}

export type PresignedUploadPart = {
  url: string;
  partNumber: number;
  expiresIn: number;
};

/**
 * Generate a presigned PUT URL for a single part of an in-progress multipart
 * upload. Part numbers are 1-indexed in S3, so callers pass `partNumber: 1`
 * for the first part. Each presign URL has a short TTL (60s default, 5 min
 * max) so a long-running upload should request new presigns near the end of
 * the window — the upload client does this batched.
 */
export async function presignUploadPart(
  key: string,
  uploadId: string,
  partNumber: number,
): Promise<PresignedUploadPart> {
  if (!storage) throw new Error("Storage is not configured");
  const url = await getSignedUrl(
    storage.client,
    new UploadPartCommand({
      Bucket: storage.bucket,
      Key: physicalKey(storage, key),
      UploadId: uploadId,
      PartNumber: partNumber,
    }),
    { expiresIn: PRESIGN_EXPIRES_SECONDS },
  );
  return { url, partNumber, expiresIn: PRESIGN_EXPIRES_SECONDS };
}

export type CompletedPart = {
  partNumber: number;
  etag: string;
};

/**
 * Finalize a multipart upload — S3 stitches the parts into a single object.
 * The client collects ETag values from each part's PUT response and passes
 * them here in order. Returns the assembled object's location (informational
 * only — the consuming code should read by `key`, not by URL).
 */
export async function completeMultipartUpload(
  key: string,
  uploadId: string,
  parts: CompletedPart[],
): Promise<void> {
  if (!storage) throw new Error("Storage is not configured");
  const sorted = [...parts].sort((a, b) => a.partNumber - b.partNumber);
  await storage.client.send(
    new CompleteMultipartUploadCommand({
      Bucket: storage.bucket,
      Key: physicalKey(storage, key),
      UploadId: uploadId,
      MultipartUpload: {
        Parts: sorted.map((p) => ({ ETag: p.etag, PartNumber: p.partNumber })),
      },
    }),
  );
}

// ---------------------------------------------------------------------------
// Range read — for serving HLS segments without buffering the whole object.
// ---------------------------------------------------------------------------

export type StorageObjectRange = {
  body: Uint8Array;
  contentType: string;
  contentLength: number;
  contentRange: string | null;
  totalSize: number | null;
};

/**
 * Fetch an object with an HTTP-style Range header. Used by the HLS segment
 * route so a player that requests `bytes=0-65535` on a large segment doesn't
 * force the server to buffer the whole file. Range is optional — pass null
 * to read the whole object. Returns null when the object doesn't exist.
 */
export async function getStorageObjectRange(
  key: string,
  range: string | null,
): Promise<StorageObjectRange | null> {
  if (!storage) throw new Error("Storage is not configured");
  try {
    const result = await storage.client.send(
      new GetObjectCommand({
        Bucket: storage.bucket,
        Key: physicalKey(storage, key),
        Range: range ?? undefined,
      }),
    );
    if (!result.Body) return null;
    const body = await result.Body.transformToByteArray();
    return {
      body,
      contentType: result.ContentType ?? "application/octet-stream",
      contentLength: result.ContentLength ?? body.byteLength,
      contentRange: result.ContentRange ?? null,
      totalSize:
        typeof result.ContentRange === "string"
          ? Number.parseInt(result.ContentRange.split("/")[1] ?? "", 10) || null
          : (result.ContentLength ?? null),
    };
  } catch (err: unknown) {
    if (isNotFoundError(err)) return null;
    throw err;
  }
}

function isNotFoundError(err: unknown): boolean {
  if (typeof err !== "object" || err === null) return false;
  const e = err as { name?: string; $metadata?: { httpStatusCode?: number } };
  return e.name === "NoSuchKey" || e.$metadata?.httpStatusCode === 404;
}

function toNodeReadable(body: unknown): NodeJS.ReadableStream {
  if (body instanceof Readable) return body;
  if (body instanceof ReadableStream) return Readable.fromWeb(body as NodeReadableStream);
  if (typeof body === "object" && body !== null && "transformToWebStream" in body) {
    const stream = (
      body as { transformToWebStream: () => NodeReadableStream<Uint8Array> }
    ).transformToWebStream();
    return Readable.fromWeb(stream);
  }
  throw new Error("Storage object body is not a readable stream");
}
