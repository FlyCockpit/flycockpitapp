import prisma from "@flycockpit/db";

import {
  abortMultipartUpload,
  deleteStorageObject,
  deleteStorageObjects,
  listIncompleteMultipartUploads,
  listStorageObjects,
  type StorageObjectListEntry,
  storage,
} from "./storage";

/**
 * Three-phase video cleanup, mirroring the asset cleanup but scoped to the
 * `videos/` and `rawVideos/` prefixes. Removing the video pattern is then a
 * single delete of this file plus the worker registration; the asset sweep
 * stays untouched.
 *
 *   Phase 1 — orphan PENDING rows. Delete Video and VideoAudioTrack rows
 *     stuck in PENDING whose heartbeat is older than the threshold. Falls
 *     back to createdAt when uploadHeartbeatAt is null. Best-effort deletes
 *     the source S3 object.
 *
 *   Phase 2 — orphan S3 objects. List every key under each prefix; delete
 *     objects whose Video row no longer exists, plus audio/subtitle artifacts
 *     whose track row no longer exists. Skip objects newer than the grace
 *     window so an in-flight transcode doesn't get its segments deleted
 *     mid-write.
 *
 *   Phase 3 — incomplete multipart uploads. Abort multiparts older than
 *     `multipartMaxAgeMs` under both prefixes.
 */

const VIDEO_OUTPUT_PREFIX = "videos/";
const VIDEO_RAW_PREFIX = "rawVideos/";

export type VideoCleanupOptions = {
  pendingMaxAgeMs?: number;
  transcodingMaxAgeMs?: number;
  objectMinAgeMs?: number;
  multipartMaxAgeMs?: number;
};

export type VideoCleanupSummary = {
  pendingVideosReaped: number;
  pendingAudioTracksReaped: number;
  staleTranscodingVideosFailed: number;
  staleTranscodingAudioTracksFailed: number;
  orphanObjectsDeleted: number;
  orphanObjectsBytes: number;
  multipartUploadsAborted: number;
};

const DEFAULTS = {
  pendingMaxAgeMs: 5 * 60_000,
  transcodingMaxAgeMs: 12 * 60 * 60_000,
  objectMinAgeMs: 30 * 60_000, // 30 min — longer than asset's 15 because
  // a transcode pass can run for ~10 min on a long source.
  multipartMaxAgeMs: 24 * 60 * 60_000,
};

export async function runVideoCleanup(
  opts: VideoCleanupOptions = {},
): Promise<VideoCleanupSummary> {
  if (!storage) throw new Error("Object storage is not configured");

  const pendingMaxAgeMs = opts.pendingMaxAgeMs ?? DEFAULTS.pendingMaxAgeMs;
  const transcodingMaxAgeMs = opts.transcodingMaxAgeMs ?? DEFAULTS.transcodingMaxAgeMs;
  const objectMinAgeMs = opts.objectMinAgeMs ?? DEFAULTS.objectMinAgeMs;
  const multipartMaxAgeMs = opts.multipartMaxAgeMs ?? DEFAULTS.multipartMaxAgeMs;

  const summary: VideoCleanupSummary = {
    pendingVideosReaped: 0,
    pendingAudioTracksReaped: 0,
    staleTranscodingVideosFailed: 0,
    staleTranscodingAudioTracksFailed: 0,
    orphanObjectsDeleted: 0,
    orphanObjectsBytes: 0,
    multipartUploadsAborted: 0,
  };

  const now = Date.now();
  const cutoff = new Date(now - pendingMaxAgeMs);

  // Phase 1a — PENDING Video rows
  const staleVideos = await prisma.video.findMany({
    where: {
      status: "PENDING",
      OR: [
        { uploadHeartbeatAt: { lt: cutoff } },
        { uploadHeartbeatAt: null, createdAt: { lt: cutoff } },
      ],
    },
    select: { id: true, sourceKey: true },
  });
  for (const v of staleVideos) {
    const reaped = await prisma.video.deleteMany({
      where: {
        id: v.id,
        status: "PENDING",
        OR: [
          { uploadHeartbeatAt: { lt: cutoff } },
          { uploadHeartbeatAt: null, createdAt: { lt: cutoff } },
        ],
      },
    });
    if (reaped.count === 0) continue;
    summary.pendingVideosReaped++;
    if (v.sourceKey) {
      await deleteStorageObject(v.sourceKey).catch(() => {});
    }
  }

  // Phase 1b — PENDING VideoAudioTrack rows
  const staleTracks = await prisma.videoAudioTrack.findMany({
    where: {
      status: "PENDING",
      OR: [
        { uploadHeartbeatAt: { lt: cutoff } },
        { uploadHeartbeatAt: null, createdAt: { lt: cutoff } },
      ],
    },
    select: { id: true, sourceKey: true },
  });
  for (const t of staleTracks) {
    const reaped = await prisma.videoAudioTrack.deleteMany({
      where: {
        id: t.id,
        status: "PENDING",
        OR: [
          { uploadHeartbeatAt: { lt: cutoff } },
          { uploadHeartbeatAt: null, createdAt: { lt: cutoff } },
        ],
      },
    });
    if (reaped.count === 0) continue;
    summary.pendingAudioTracksReaped++;
    if (t.sourceKey) {
      await deleteStorageObject(t.sourceKey).catch(() => {});
    }
  }

  // Phase 1c — rows left TRANSCODING after a worker crash/stalled job.
  const transcodingCutoff = new Date(now - transcodingMaxAgeMs);
  const staleVideoTranscodes = await prisma.video.updateMany({
    where: { status: "TRANSCODING", updatedAt: { lt: transcodingCutoff } },
    data: {
      status: "FAILED",
      failureReason: "Transcode timed out or the worker exited before reporting failure.",
    },
  });
  summary.staleTranscodingVideosFailed = staleVideoTranscodes.count;

  const staleAudioTranscodes = await prisma.videoAudioTrack.updateMany({
    where: { status: "TRANSCODING", updatedAt: { lt: transcodingCutoff } },
    data: {
      status: "FAILED",
      failureReason: "Audio transcode timed out or the worker exited before reporting failure.",
    },
  });
  summary.staleTranscodingAudioTracksFailed = staleAudioTranscodes.count;

  // Phase 2 — orphan S3 objects. We scan both prefixes and check whether the
  // owning Video row still exists. For live videos, audio/subtitle sub-prefixes
  // are also checked against their row-level owners so failed best-effort
  // cleanup after track deletion does not leak forever.
  const objectAgeCutoff = new Date(now - objectMinAgeMs);
  const OBJECT_BATCH_SIZE = 1000;
  let objectBatch: StorageObjectListEntry[] = [];

  const processObjectBatch = async () => {
    if (objectBatch.length === 0) return;
    const batch = objectBatch;
    objectBatch = [];

    const parsed = batch.flatMap((obj) => {
      const parts = obj.key.split("/");
      const videoId = parts[1];
      return videoId ? [{ obj, parts, videoId }] : [];
    });
    if (parsed.length === 0) return;

    const videoIds = [...new Set(parsed.map((entry) => entry.videoId))];
    const [videos, audioTracks, subtitleTracks] = await Promise.all([
      prisma.video.findMany({ where: { id: { in: videoIds } }, select: { id: true } }),
      prisma.videoAudioTrack.findMany({
        where: { videoId: { in: videoIds } },
        select: { videoId: true, locale: true, sourceKey: true },
      }),
      prisma.videoSubtitleTrack.findMany({
        where: { videoId: { in: videoIds } },
        select: { storageKey: true },
      }),
    ]);
    const liveVideoIds = new Set(videos.map((video) => video.id));
    const audioSourceKeys = new Set(
      audioTracks.flatMap((track) => (track.sourceKey === null ? [] : [track.sourceKey])),
    );
    const audioLocales = new Set(audioTracks.map((track) => `${track.videoId}/${track.locale}`));
    const subtitleKeys = new Set(subtitleTracks.map((track) => track.storageKey));

    const candidates: typeof parsed = [];
    for (const entry of parsed) {
      const trackObject = parseTrackObjectKey(entry.parts, entry.obj.key, entry.videoId);
      if (liveVideoIds.has(entry.videoId)) {
        if (!trackObject) continue;
        const referenced =
          trackObject.kind === "rawAudioSource"
            ? audioSourceKeys.has(entry.obj.key)
            : trackObject.kind === "audioOutput"
              ? audioLocales.has(`${entry.videoId}/${trackObject.locale}`)
              : subtitleKeys.has(entry.obj.key);
        if (referenced) continue;
      }
      candidates.push(entry);
    }

    const confirmed: StorageObjectListEntry[] = [];
    for (const entry of candidates) {
      const video = await prisma.video.findUnique({
        where: { id: entry.videoId },
        select: { id: true },
      });
      const trackObject = parseTrackObjectKey(entry.parts, entry.obj.key, entry.videoId);
      if (
        video &&
        (!trackObject || !(await isUnreferencedTrackObject(trackObject, entry.videoId)))
      ) {
        continue;
      }
      confirmed.push(entry.obj);
    }
    if (confirmed.length === 0) return;

    try {
      const deletion = await deleteStorageObjects(confirmed.map((obj) => obj.key));
      const failedKeys = new Set(deletion.errors.map((err) => err.key));
      for (const obj of confirmed) {
        if (failedKeys.has(obj.key)) continue;
        summary.orphanObjectsDeleted++;
        summary.orphanObjectsBytes += obj.size;
      }
    } catch {
      // Best-effort; the next cron pass retries anything left behind.
    }
  };

  for (const prefix of [VIDEO_OUTPUT_PREFIX, VIDEO_RAW_PREFIX]) {
    for await (const obj of listStorageObjects(prefix)) {
      if (obj.lastModified && obj.lastModified >= objectAgeCutoff) continue;
      objectBatch.push(obj);
      if (objectBatch.length >= OBJECT_BATCH_SIZE) await processObjectBatch();
    }
    await processObjectBatch();
  }

  // Phase 3 — incomplete multipart uploads
  const multipartCutoff = new Date(now - multipartMaxAgeMs);
  for (const prefix of [VIDEO_OUTPUT_PREFIX, VIDEO_RAW_PREFIX]) {
    for await (const upload of listIncompleteMultipartUploads(prefix)) {
      if (upload.initiated && upload.initiated >= multipartCutoff) continue;
      await abortMultipartUpload(upload.key, upload.uploadId).catch(() => {});
      summary.multipartUploadsAborted++;
    }
  }

  return summary;
}

export type TrackObjectKey =
  | { kind: "rawAudioSource"; key: string }
  | { kind: "audioOutput"; locale: string }
  | { kind: "subtitle"; key: string };

export function parseTrackObjectKey(
  parts: string[],
  key: string,
  videoId: string,
): TrackObjectKey | null {
  if (parts[0] === "rawVideos" && parts[1] === videoId && parts[2] === "a") {
    return { kind: "rawAudioSource", key };
  }
  if (parts[0] === "videos" && parts[1] === videoId && parts[2] === "a" && parts[3]) {
    return { kind: "audioOutput", locale: parts[3] };
  }
  if (parts[0] === "videos" && parts[1] === videoId && parts[2] === "t") {
    return { kind: "subtitle", key };
  }
  return null;
}

async function isUnreferencedTrackObject(
  trackObject: TrackObjectKey,
  videoId: string,
): Promise<boolean> {
  if (trackObject.kind === "rawAudioSource") {
    const track = await prisma.videoAudioTrack.findFirst({
      where: { videoId, sourceKey: trackObject.key },
      select: { id: true },
    });
    return !track;
  }

  if (trackObject.kind === "audioOutput") {
    const track = await prisma.videoAudioTrack.findUnique({
      where: { videoId_locale: { videoId, locale: trackObject.locale } },
      select: { id: true },
    });
    return !track;
  }

  const track = await prisma.videoSubtitleTrack.findFirst({
    where: { videoId, storageKey: trackObject.key },
    select: { id: true },
  });
  return !track;
}
