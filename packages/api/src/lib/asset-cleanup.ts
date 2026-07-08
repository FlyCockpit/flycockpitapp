import prisma from "@flycockpit/db";

import {
  abortMultipartUpload,
  deleteStorageObject,
  listIncompleteMultipartUploads,
  listStorageObjects,
  storage,
} from "./storage";

/**
 * Three-phase asset cleanup. Shared between the admin trigger and the cron.
 *
 * Phase 1 — orphan PENDING rows. Delete Asset rows still in PENDING whose
 *   heartbeat is older than `pendingMaxAgeMs`. Falls back to `createdAt` for
 *   rows that predate the heartbeat field (`uploadHeartbeatAt IS NULL`). Each
 *   deleted row's storage object is best-effort removed too.
 *
 * Phase 2 — orphan S3 objects. List every key under the asset prefix and
 *   delete those with no Asset row whose `storageKey` matches. To avoid
 *   racing against an in-flight upload, the row is re-checked at delete time
 *   (not from a cached snapshot), and objects newer than
 *   `objectMinAgeMs` are skipped entirely.
 *
 * Phase 3 — incomplete multipart uploads. Abort any multipart upload older
 *   than `multipartMaxAgeMs`. Flycockpit does not use multipart uploads, so
 *   this is a defensive sweep for buckets shared with other tools.
 */

const ASSET_KEY_PREFIX = "assets/";

export type CleanupOptions = {
  /**
   * Age threshold for a PENDING Asset row to be reaped. Compared against
   * `uploadHeartbeatAt` (or `createdAt` when the heartbeat is null).
   * Default: 5 minutes — the heartbeat interval is 60s, so this tolerates
   * ~5 missed beats.
   */
  pendingMaxAgeMs?: number;
  /**
   * Skip S3 objects newer than this. Guards against an upload that arrived
   * in S3 between phase 1 and phase 2 (PENDING row still being created, or
   * presigned URL just used). Default: 15 minutes — longer than the
   * presigned URL's 5-minute TTL plus a generous buffer.
   */
  objectMinAgeMs?: number;
  /**
   * Age threshold for incomplete multipart uploads. Default: 24 hours.
   */
  multipartMaxAgeMs?: number;
};

const DEFAULTS = {
  pendingMaxAgeMs: 5 * 60 * 1000,
  objectMinAgeMs: 15 * 60 * 1000,
  multipartMaxAgeMs: 24 * 60 * 60 * 1000,
} as const;

function resolveOpts(opts: CleanupOptions | undefined): Required<CleanupOptions> {
  return {
    pendingMaxAgeMs: opts?.pendingMaxAgeMs ?? DEFAULTS.pendingMaxAgeMs,
    objectMinAgeMs: opts?.objectMinAgeMs ?? DEFAULTS.objectMinAgeMs,
    multipartMaxAgeMs: opts?.multipartMaxAgeMs ?? DEFAULTS.multipartMaxAgeMs,
  };
}

export type CleanupCandidate = {
  /** What kind of thing this is. */
  kind: "pending-row" | "orphan-object" | "incomplete-multipart";
  /** Asset id for `pending-row`, S3 key for the other two. */
  id: string;
  /** Bytes (rows: declared size; objects: S3-reported size; multipart: 0). */
  size: number;
  /** When the candidate was last touched (heartbeat / lastModified / initiated). */
  ageReference: Date | null;
};

export type CleanupSummary = {
  pendingRows: { count: number; bytes: number; sample: CleanupCandidate[] };
  orphanObjects: { count: number; bytes: number; sample: CleanupCandidate[] };
  incompleteMultipart: { count: number; sample: CleanupCandidate[] };
};

const SAMPLE_LIMIT = 25;

function emptySummary(): CleanupSummary {
  return {
    pendingRows: { count: 0, bytes: 0, sample: [] },
    orphanObjects: { count: 0, bytes: 0, sample: [] },
    incompleteMultipart: { count: 0, sample: [] },
  };
}

/**
 * Inspect the bucket without touching anything. Returns counts, byte totals,
 * and a sample of up to 25 candidates per category for an admin to preview.
 */
export async function dryRunCleanup(opts?: CleanupOptions): Promise<CleanupSummary> {
  if (!storage) throw new Error("Storage is not configured");
  const o = resolveOpts(opts);
  const now = Date.now();
  const summary = emptySummary();

  const pendingCutoff = new Date(now - o.pendingMaxAgeMs);
  const pendingRows = await prisma.asset.findMany({
    where: {
      status: "PENDING",
      OR: [
        { uploadHeartbeatAt: { lt: pendingCutoff } },
        { AND: [{ uploadHeartbeatAt: null }, { createdAt: { lt: pendingCutoff } }] },
      ],
    },
    select: { id: true, size: true, uploadHeartbeatAt: true, createdAt: true },
  });
  summary.pendingRows.count = pendingRows.length;
  for (const row of pendingRows) {
    const size = Number(row.size);
    summary.pendingRows.bytes += size;
    if (summary.pendingRows.sample.length < SAMPLE_LIMIT) {
      summary.pendingRows.sample.push({
        kind: "pending-row",
        id: row.id,
        size,
        ageReference: row.uploadHeartbeatAt ?? row.createdAt,
      });
    }
  }

  const objectCutoff = new Date(now - o.objectMinAgeMs);
  const knownKeys = await loadKnownStorageKeys();
  for await (const obj of listStorageObjects(ASSET_KEY_PREFIX)) {
    if (knownKeys.has(obj.key)) continue;
    if (obj.lastModified && obj.lastModified > objectCutoff) continue;
    summary.orphanObjects.count++;
    summary.orphanObjects.bytes += obj.size;
    if (summary.orphanObjects.sample.length < SAMPLE_LIMIT) {
      summary.orphanObjects.sample.push({
        kind: "orphan-object",
        id: obj.key,
        size: obj.size,
        ageReference: obj.lastModified,
      });
    }
  }

  const multipartCutoff = new Date(now - o.multipartMaxAgeMs);
  for await (const upload of listIncompleteMultipartUploads(ASSET_KEY_PREFIX)) {
    if (upload.initiated && upload.initiated > multipartCutoff) continue;
    summary.incompleteMultipart.count++;
    if (summary.incompleteMultipart.sample.length < SAMPLE_LIMIT) {
      summary.incompleteMultipart.sample.push({
        kind: "incomplete-multipart",
        id: `${upload.key}|${upload.uploadId}`,
        size: 0,
        ageReference: upload.initiated,
      });
    }
  }

  return summary;
}

export type CleanupResult = {
  pendingRowsDeleted: number;
  pendingStorageObjectsDeleted: number;
  pendingStorageObjectsFailed: number;
  orphanObjectsDeleted: number;
  orphanObjectsFailed: number;
  multipartAborted: number;
  multipartAbortFailed: number;
  /** Total bytes freed (declared sizes for rows + S3-reported for objects). */
  bytesFreed: number;
};

function emptyResult(): CleanupResult {
  return {
    pendingRowsDeleted: 0,
    pendingStorageObjectsDeleted: 0,
    pendingStorageObjectsFailed: 0,
    orphanObjectsDeleted: 0,
    orphanObjectsFailed: 0,
    multipartAborted: 0,
    multipartAbortFailed: 0,
    bytesFreed: 0,
  };
}

/**
 * Execute the cleanup. Phase order matters:
 *   1. Reap PENDING rows first → their storage keys become orphans, which
 *      phase 2 then deletes.
 *   2. List S3 and check each candidate against a fresh DB lookup (the snapshot
 *      taken at LIST time can be minutes old on a big bucket; a re-check at
 *      delete time keeps in-flight uploads safe even from late-arriving rows).
 *   3. Abort old incomplete multipart uploads.
 */
export async function runCleanup(opts?: CleanupOptions): Promise<CleanupResult> {
  if (!storage) throw new Error("Storage is not configured");
  const o = resolveOpts(opts);
  const now = Date.now();
  const result = emptyResult();

  const pendingCutoff = new Date(now - o.pendingMaxAgeMs);
  const candidatePending = await prisma.asset.findMany({
    where: {
      status: "PENDING",
      OR: [
        { uploadHeartbeatAt: { lt: pendingCutoff } },
        { AND: [{ uploadHeartbeatAt: null }, { createdAt: { lt: pendingCutoff } }] },
      ],
    },
    select: { id: true, storageKey: true, size: true },
  });
  for (const row of candidatePending) {
    // Re-check the row state — a heartbeat could have landed between LIST
    // and DELETE. Use a conditional updateMany so a concurrent heartbeat
    // beats us and the row stays intact.
    const reaped = await prisma.asset.deleteMany({
      where: {
        id: row.id,
        status: "PENDING",
        OR: [
          { uploadHeartbeatAt: { lt: pendingCutoff } },
          { AND: [{ uploadHeartbeatAt: null }, { createdAt: { lt: pendingCutoff } }] },
        ],
      },
    });
    if (reaped.count === 0) continue;
    result.pendingRowsDeleted++;
    result.bytesFreed += Number(row.size);
    try {
      await deleteStorageObject(row.storageKey);
      result.pendingStorageObjectsDeleted++;
    } catch (err) {
      result.pendingStorageObjectsFailed++;
      console.warn("[asset-cleanup] storage delete failed for pending row", {
        id: row.id,
        key: row.storageKey,
        err,
      });
    }
  }

  const objectCutoff = new Date(now - o.objectMinAgeMs);
  for await (const obj of listStorageObjects(ASSET_KEY_PREFIX)) {
    if (obj.lastModified && obj.lastModified > objectCutoff) continue;
    // Re-check at delete time: a row may have been created after we kicked
    // off the LIST, especially on big buckets where the iteration takes long.
    const existing = await prisma.asset.findUnique({
      where: { storageKey: obj.key },
      select: { id: true },
    });
    if (existing) continue;
    try {
      await deleteStorageObject(obj.key);
      result.orphanObjectsDeleted++;
      result.bytesFreed += obj.size;
    } catch (err) {
      result.orphanObjectsFailed++;
      console.warn("[asset-cleanup] storage delete failed for orphan object", {
        key: obj.key,
        err,
      });
    }
  }

  const multipartCutoff = new Date(now - o.multipartMaxAgeMs);
  for await (const upload of listIncompleteMultipartUploads(ASSET_KEY_PREFIX)) {
    if (upload.initiated && upload.initiated > multipartCutoff) continue;
    try {
      await abortMultipartUpload(upload.key, upload.uploadId);
      result.multipartAborted++;
    } catch (err) {
      result.multipartAbortFailed++;
      console.warn("[asset-cleanup] abort multipart failed", {
        key: upload.key,
        uploadId: upload.uploadId,
        err,
      });
    }
  }

  return result;
}

/**
 * Load every storageKey currently in the Asset table into an in-memory Set.
 * Used only by `dryRunCleanup` — the executing path does per-key lookups
 * instead, since the LIST iteration can take long enough on a big bucket
 * that a snapshot would race against new uploads.
 */
async function loadKnownStorageKeys(): Promise<Set<string>> {
  const rows = await prisma.asset.findMany({ select: { storageKey: true } });
  return new Set(rows.map((r) => r.storageKey));
}
