import { isAdminRole } from "@flycockpit/auth/roles";
import { isSupportedLocale, SUPPORTED_LOCALES } from "@flycockpit/config/locales";
import prisma from "@flycockpit/db";
import { env, VIDEO_ENABLE_4K } from "@flycockpit/env/server";
import {
  cleanupVideosQueue,
  transcodeAudioTrackQueue,
  transcodeVideoQueue,
} from "@flycockpit/queue";
import { ORPCError } from "@orpc/server";
import { z } from "zod";

import { adminOr404Procedure, protectedProcedure, publicProcedure } from "../index";
import {
  abortMultipartUpload,
  createMultipartUpload,
  deleteStorageObject,
  headStorageObject,
  listStorageObjects,
} from "../lib/storage";
import {
  abortVideoUpload,
  authorizeVideoRead,
  completeVideoUpload,
  heartbeatVideoUpload,
  loadVideoMeta,
  presignVideoUploadParts,
  startVideoUpload,
  toVideoMeta,
  type VideoLadderPolicy,
  type VideoMeta,
  type VideoSubtitleKind,
  type Viewer,
  videoStorageKeys,
} from "../lib/videos";

/**
 * Video pattern oRPC router. Read paths are gated through `authorizeVideoRead`
 * in the lib module; write paths (start/complete upload, add tracks, change
 * visibility, delete) sit here so they pick up the same protectedProcedure
 * middleware as the rest of the API.
 *
 * Upload flow:
 *   1. `start` — creates a PENDING Video row + initiates an S3 multipart
 *      upload. Returns { videoId, uploadId, sourceKey }.
 *   2. `presignParts` — issues presigned URLs for a batch of part numbers.
 *      Client PUTs each, collects ETag.
 *   3. `complete` — finalizes the multipart upload, flips Video to
 *      TRANSCODING, enqueues a `transcode-video` job. The worker takes it
 *      from here.
 *   4. `heartbeat` — bumps `uploadHeartbeatAt` every 60s so the cleanup
 *      sweep doesn't reap an in-progress upload.
 */

const idSchema = z.string().min(1);
const visibilitySchema = z.enum(["PUBLIC", "RESTRICTED"]);
const ladderPolicySchema = z.enum(["STANDARD", "INCLUDE_4K"]);
const subtitleKindSchema = z.enum(["SUBTITLES", "CAPTIONS", "DESCRIPTIONS"]);
const trackLabelSchema = z
  .string()
  .min(1)
  .max(100)
  .refine((label) => !hasControlCharacter(label), {
    message: "Track labels cannot contain control characters.",
  });
const localeSchema = z
  .string()
  .min(2)
  .max(10)
  .refine((v) => isSupportedLocale(v), {
    message: `Locale must be one of ${SUPPORTED_LOCALES.join(", ")}`,
  });

function isUniqueConstraintError(err: unknown): boolean {
  return typeof err === "object" && err !== null && "code" in err && err.code === "P2002";
}

function hasControlCharacter(value: string): boolean {
  for (const char of value) {
    const code = char.charCodeAt(0);
    if (code < 32 || code === 127) return true;
  }
  return false;
}

function viewerFromContext(context: {
  session: { user: { id: string; role?: string | null } } | null | undefined;
}): Viewer {
  if (!context.session?.user) return { kind: "anonymous" };
  return {
    kind: "user",
    userId: context.session.user.id,
    role: context.session.user.role ?? "user",
  };
}

function isOwnerOrAdmin(
  meta: { ownerId: string | null },
  context: { session: { user: { id: string; role?: string | null } } },
): boolean {
  if (isAdminRole(context.session.user.role)) return true;
  return meta.ownerId === context.session.user.id;
}

function serializeVideo(meta: VideoMeta) {
  return {
    id: meta.id,
    title: meta.title,
    description: meta.description,
    status: meta.status,
    failureReason: meta.failureReason,
    visibility: meta.visibility,
    ownerId: meta.ownerId,
    sourceLocale: meta.sourceLocale,
    durationSeconds: meta.durationSeconds,
    width: meta.width,
    height: meta.height,
    posterAssetId: meta.posterAssetId,
    ladderPolicy: meta.ladderPolicy,
    // Convenience URLs the client uses to feed the HLS player + thumbnails.
    playlistUrl: `/api/videos/${meta.id}/playlist.m3u8`,
    thumbnailsUrl: `/api/videos/${meta.id}/thumbs.vtt`,
    posterUrl: `/api/videos/${meta.id}/poster`,
  };
}

export const videosRouter = {
  // -------------------------------------------------------------------------
  // Read
  // -------------------------------------------------------------------------

  list: protectedProcedure
    .input(
      z
        .object({
          limit: z.number().int().min(1).max(100).default(20),
          cursor: idSchema.optional(),
          mineOnly: z.boolean().default(false),
        })
        .optional(),
    )
    .handler(async ({ input, context }) => {
      const limit = input?.limit ?? 20;
      const cursor = input?.cursor;
      const isAdmin = isAdminRole(context.session.user.role);

      // mineOnly means strictly uploaded/owned by the caller.
      // Otherwise non-admins see their own + PUBLIC READY videos; admins see everything.
      const where = (() => {
        if (input?.mineOnly) {
          return { ownerId: context.session.user.id };
        }
        if (!isAdmin) {
          return {
            OR: [
              { ownerId: context.session.user.id },
              { visibility: "PUBLIC" as const, status: "READY" as const },
            ],
          };
        }
        return {};
      })();

      const rows = await prisma.video.findMany({
        where,
        orderBy: [{ createdAt: "desc" }, { id: "desc" }],
        take: limit + 1,
        ...(cursor ? { cursor: { id: cursor }, skip: 1 } : {}),
      });

      const hasMore = rows.length > limit;
      const slice = hasMore ? rows.slice(0, limit) : rows;
      return {
        items: slice.map((r) => serializeVideo(toVideoMeta(r))),
        nextCursor: hasMore ? (slice[slice.length - 1]?.id ?? null) : null,
      };
    }),

  /**
   * Public-facing get — used by both the watch route and the admin panel.
   * Goes through `authorizeVideoRead` so a non-admin can never observe a
   * RESTRICTED video they don't own.
   */
  get: publicProcedure.input(z.object({ id: idSchema })).handler(async ({ input, context }) => {
    const viewer = viewerFromContext(context);
    const meta = await authorizeVideoRead(input.id, viewer).catch((err) => {
      if (err && typeof err === "object" && "code" in err && err.code === "NOT_FOUND") {
        throw new ORPCError("NOT_FOUND", { message: "Video not found" });
      }
      if (err && typeof err === "object" && "code" in err && err.code === "FORBIDDEN") {
        throw new ORPCError("NOT_FOUND", { message: "Video not found" });
      }
      throw err;
    });

    const [audioTracks, subtitleTracks, renditions] = await Promise.all([
      prisma.videoAudioTrack.findMany({
        where: { videoId: meta.id },
        orderBy: { createdAt: "asc" },
      }),
      prisma.videoSubtitleTrack.findMany({
        where: { videoId: meta.id },
        orderBy: { createdAt: "asc" },
      }),
      prisma.videoRendition.findMany({
        where: { videoId: meta.id },
        orderBy: { height: "asc" },
      }),
    ]);

    return {
      ...serializeVideo(meta),
      audioTracks: audioTracks.map((a) => ({
        id: a.id,
        locale: a.locale,
        label: a.label,
        isDefault: a.isDefault,
        status: String(a.status),
        failureReason: a.failureReason,
      })),
      subtitleTracks: subtitleTracks.map((s) => ({
        id: s.id,
        locale: s.locale,
        label: s.label,
        kind: String(s.kind) as VideoSubtitleKind,
        isDefault: s.isDefault,
        url: `/api/videos/${meta.id}/t/${s.locale}.${String(s.kind).toLowerCase()}.vtt`,
      })),
      renditions: renditions.map((r) => ({
        height: r.height,
        width: r.width,
        bandwidth: r.bandwidth,
      })),
    };
  }),

  // -------------------------------------------------------------------------
  // Upload
  // -------------------------------------------------------------------------

  start: protectedProcedure
    .input(
      z.object({
        title: z.string().min(1).max(200),
        description: z.string().max(2000).optional().nullable(),
        visibility: visibilitySchema.default("RESTRICTED"),
        sourceLocale: localeSchema,
        sourceMimeType: z.string().min(1),
        sourceSize: z
          .number()
          .int()
          .positive()
          .max(env.VIDEO_UPLOAD_MAX_BYTES, {
            message: `File exceeds the ${Math.round(
              env.VIDEO_UPLOAD_MAX_BYTES / (1024 * 1024 * 1024),
            )} GB upload limit.`,
          }),
        ladderPolicy: ladderPolicySchema.default("STANDARD"),
      }),
    )
    .handler(async ({ input, context }) => {
      const ladderPolicy: VideoLadderPolicy =
        input.ladderPolicy === "INCLUDE_4K" && VIDEO_ENABLE_4K ? "INCLUDE_4K" : "STANDARD";
      const result = await startVideoUpload({
        ownerId: context.session.user.id,
        title: input.title,
        description: input.description ?? null,
        visibility: input.visibility,
        sourceLocale: input.sourceLocale,
        sourceMimeType: input.sourceMimeType,
        sourceSize: input.sourceSize,
        ladderPolicy,
      });
      return result;
    }),

  presignParts: protectedProcedure
    .input(
      z.object({
        videoId: idSchema,
        uploadId: z.string().min(1),
        partNumbers: z.array(z.number().int().positive().max(10000)).min(1).max(50),
      }),
    )
    .handler(async ({ input, context }) => {
      const viewer = viewerFromContext(context);
      const parts = await presignVideoUploadParts({
        videoId: input.videoId,
        uploadId: input.uploadId,
        partNumbers: input.partNumbers,
        viewer,
      });
      return { parts };
    }),

  complete: protectedProcedure
    .input(
      z.object({
        videoId: idSchema,
        uploadId: z.string().min(1),
        parts: z
          .array(
            z.object({
              partNumber: z.number().int().positive(),
              etag: z.string().min(1),
            }),
          )
          .min(1),
      }),
    )
    .handler(async ({ input, context }) => {
      const viewer = viewerFromContext(context);
      const meta = await completeVideoUpload({
        videoId: input.videoId,
        uploadId: input.uploadId,
        parts: input.parts,
        viewer,
      });
      transcodeVideoQueue
        .add("transcode-video", { videoId: meta.id })
        .catch((err) => console.warn("[videos] enqueue transcode-video failed:", err));
      return serializeVideo(meta);
    }),

  abort: protectedProcedure
    .input(z.object({ videoId: idSchema, uploadId: z.string().min(1) }))
    .handler(async ({ input, context }) => {
      const viewer = viewerFromContext(context);
      await abortVideoUpload({
        videoId: input.videoId,
        uploadId: input.uploadId,
        viewer,
      });
      return { ok: true };
    }),

  heartbeat: protectedProcedure
    .input(z.object({ videoId: idSchema }))
    .handler(async ({ input, context }) => {
      const viewer = viewerFromContext(context);
      await heartbeatVideoUpload({ videoId: input.videoId, viewer });
      return { ok: true };
    }),

  // -------------------------------------------------------------------------
  // Mutations (owner / admin)
  // -------------------------------------------------------------------------

  update: protectedProcedure
    .input(
      z.object({
        id: idSchema,
        title: z.string().min(1).max(200).optional(),
        description: z.string().max(2000).nullable().optional(),
        visibility: visibilitySchema.optional(),
        sourceLocale: localeSchema.optional(),
      }),
    )
    .handler(async ({ input, context }) => {
      const meta = await loadVideoMeta(input.id);
      if (!meta) throw new ORPCError("NOT_FOUND");
      if (!isOwnerOrAdmin(meta, context)) throw new ORPCError("NOT_FOUND");

      const updated = await prisma.video.update({
        where: { id: input.id },
        data: {
          title: input.title ?? undefined,
          description: input.description === undefined ? undefined : input.description,
          visibility: input.visibility ?? undefined,
          sourceLocale: input.sourceLocale ?? undefined,
        },
      });
      return serializeVideo(toVideoMeta(updated));
    }),

  delete: protectedProcedure
    .input(z.object({ id: idSchema }))
    .handler(async ({ input, context }) => {
      const meta = await loadVideoMeta(input.id);
      if (!meta) throw new ORPCError("NOT_FOUND");
      if (!isOwnerOrAdmin(meta, context)) throw new ORPCError("NOT_FOUND");

      await prisma.video.delete({ where: { id: input.id } });
      // Best-effort sweep after the row is gone. If storage cleanup fails,
      // cleanup-videos can still reap objects by observing the missing row.
      await deleteVideoStorage(input.id).catch((err) =>
        console.warn("[videos] storage cleanup failed:", err),
      );
      return { ok: true };
    }),

  // -------------------------------------------------------------------------
  // Audio tracks (dubs)
  // -------------------------------------------------------------------------

  /**
   * Start uploading an additional audio track. The client posts the file via
   * presigned multipart upload parts. On completion, call `finalizeAudioTrack`
   * to enqueue transcoding.
   */
  startAudioTrack: protectedProcedure
    .input(
      z.object({
        videoId: idSchema,
        locale: localeSchema,
        label: trackLabelSchema,
        mimeType: z.string().min(1),
        size: z.number().int().positive().max(env.VIDEO_UPLOAD_MAX_BYTES, {
          message: `File exceeds the upload limit.`,
        }),
      }),
    )
    .handler(async ({ input, context }) => {
      const meta = await loadVideoMeta(input.videoId);
      if (!meta) throw new ORPCError("NOT_FOUND");
      if (!isOwnerOrAdmin(meta, context)) throw new ORPCError("NOT_FOUND");
      if (meta.status !== "READY") {
        throw new ORPCError("BAD_REQUEST", {
          message: "Video must finish processing before adding audio tracks.",
        });
      }
      if (meta.sourceLocale === input.locale) {
        throw new ORPCError("BAD_REQUEST", {
          message: "The source-language audio track already exists.",
        });
      }

      // Use a presigned multipart upload for audio dubs. Re-upload semantics:
      // we swap the DB row in a single transaction so two concurrent callers
      // can't both win — the unique (videoId, locale) constraint serializes
      // them and the loser gets P2002, which we surface as CONFLICT.
      //
      const trackId = crypto.randomUUID();
      const storageKey = videoStorageKeys.rawAudio(input.videoId, trackId);
      const { uploadId } = await createMultipartUpload(storageKey, input.mimeType);
      let deletedSourceKey: string | null = null;

      try {
        await prisma.$transaction(async (tx) => {
          const existing = await tx.videoAudioTrack.findUnique({
            where: { videoId_locale: { videoId: input.videoId, locale: input.locale } },
          });
          if (existing) {
            deletedSourceKey = existing.sourceKey ?? null;
            // Catch P2025 in case another tab's transaction already deleted
            // this row before we got the lock.
            await tx.videoAudioTrack.delete({ where: { id: existing.id } }).catch(() => {});
          }
          await tx.videoAudioTrack.create({
            data: {
              id: trackId,
              videoId: input.videoId,
              locale: input.locale,
              label: input.label,
              isDefault: false,
              status: "PENDING",
              sourceKey: storageKey,
              sourceSize: BigInt(input.size),
              sourceMimeType: input.mimeType,
              uploadHeartbeatAt: new Date(),
            },
          });
        });
      } catch (err) {
        // Whatever happened, we've already initiated a multipart upload that
        // is now orphaned — abort it so we don't lean on the 24h cleanup.
        await abortMultipartUpload(storageKey, uploadId).catch(() => {});
        if (isUniqueConstraintError(err)) {
          throw new ORPCError("CONFLICT", {
            message: "Another upload for this audio track is in progress. Try again.",
          });
        }
        throw err;
      }

      // Transaction committed — sweep the prior row's stored bytes + segments.
      // Best-effort; the cleanup cron also picks up orphans.
      if (deletedSourceKey) {
        await deleteStorageObject(deletedSourceKey).catch(() => {});
      }
      await deleteAudioTrackStorage(input.videoId, input.locale).catch(() => {});

      return { audioTrackId: trackId, uploadId, storageKey };
    }),

  presignAudioTrackParts: protectedProcedure
    .input(
      z.object({
        audioTrackId: idSchema,
        uploadId: z.string().min(1),
        partNumbers: z.array(z.number().int().positive().max(10000)).min(1).max(50),
      }),
    )
    .handler(async ({ input, context }) => {
      const track = await prisma.videoAudioTrack.findUnique({
        where: { id: input.audioTrackId },
        include: { Video: { select: { ownerId: true } } },
      });
      if (!track?.sourceKey) throw new ORPCError("NOT_FOUND");
      if (!isOwnerOrAdmin({ ownerId: track.Video.ownerId }, context)) {
        throw new ORPCError("NOT_FOUND");
      }
      if (String(track.status) !== "PENDING") {
        throw new ORPCError("BAD_REQUEST", { message: "Upload already finalized" });
      }
      await prisma.videoAudioTrack.update({
        where: { id: track.id },
        data: { uploadHeartbeatAt: new Date() },
      });
      const { presignUploadPart } = await import("../lib/storage");
      const parts = await Promise.all(
        input.partNumbers.map((partNumber) =>
          presignUploadPart(track.sourceKey!, input.uploadId, partNumber),
        ),
      );
      return { parts };
    }),

  abortAudioTrack: protectedProcedure
    .input(z.object({ audioTrackId: idSchema, uploadId: z.string().min(1) }))
    .handler(async ({ input, context }) => {
      const track = await prisma.videoAudioTrack.findUnique({
        where: { id: input.audioTrackId },
        include: { Video: { select: { ownerId: true } } },
      });
      if (!track?.sourceKey) throw new ORPCError("NOT_FOUND");
      if (!isOwnerOrAdmin({ ownerId: track.Video.ownerId }, context)) {
        throw new ORPCError("NOT_FOUND");
      }
      if (String(track.status) !== "PENDING") {
        return { ok: true };
      }
      await abortMultipartUpload(track.sourceKey, input.uploadId).catch(() => {});
      // Atomic check-and-delete: if a worker flipped status out of PENDING
      // between the check above and now, leave the row alone.
      const deleted = await prisma.videoAudioTrack
        .deleteMany({ where: { id: track.id, status: "PENDING" } })
        .catch(() => ({ count: 0 }));
      if (deleted.count > 0) {
        await deleteStorageObject(track.sourceKey).catch(() => {});
      }
      return { ok: true };
    }),

  heartbeatAudioTrack: protectedProcedure
    .input(z.object({ audioTrackId: idSchema }))
    .handler(async ({ input, context }) => {
      const track = await prisma.videoAudioTrack.findUnique({
        where: { id: input.audioTrackId },
        include: { Video: { select: { ownerId: true } } },
      });
      if (!track) throw new ORPCError("NOT_FOUND");
      if (!isOwnerOrAdmin({ ownerId: track.Video.ownerId }, context)) {
        throw new ORPCError("NOT_FOUND");
      }
      if (String(track.status) !== "PENDING") return { ok: true };
      await prisma.videoAudioTrack.update({
        where: { id: track.id },
        data: { uploadHeartbeatAt: new Date() },
      });
      return { ok: true };
    }),

  finalizeAudioTrack: protectedProcedure
    .input(
      z.object({
        audioTrackId: idSchema,
        uploadId: z.string().min(1),
        parts: z
          .array(
            z.object({
              partNumber: z.number().int().positive(),
              etag: z.string().min(1),
            }),
          )
          .min(1),
      }),
    )
    .handler(async ({ input, context }) => {
      const track = await prisma.videoAudioTrack.findUnique({
        where: { id: input.audioTrackId },
        include: { Video: { select: { ownerId: true } } },
      });
      if (!track?.sourceKey) throw new ORPCError("NOT_FOUND");
      if (!isOwnerOrAdmin({ ownerId: track.Video.ownerId }, context)) {
        throw new ORPCError("NOT_FOUND");
      }
      if (String(track.status) !== "PENDING") {
        throw new ORPCError("BAD_REQUEST", { message: "Already finalized" });
      }
      const { completeMultipartUpload } = await import("../lib/storage");
      await completeMultipartUpload(track.sourceKey, input.uploadId, input.parts);
      const head = await headStorageObject(track.sourceKey);
      if (!head) throw new ORPCError("CONFLICT", { message: "Upload missing" });
      const expectedSize = track.sourceSize === null ? null : Number(track.sourceSize);
      if (expectedSize !== null && head.contentLength !== expectedSize) {
        throw new ORPCError("CONFLICT", {
          message: "Uploaded audio size does not match the expected size.",
        });
      }

      const updated = await prisma.videoAudioTrack.update({
        where: { id: track.id },
        data: {
          status: "TRANSCODING",
          sourceSize: BigInt(head.contentLength),
          uploadHeartbeatAt: null,
        },
      });

      transcodeAudioTrackQueue
        .add("transcode-audio-track", { audioTrackId: updated.id })
        .catch((err) => console.warn("[videos] enqueue transcode-audio-track failed:", err));
      return { id: updated.id, status: String(updated.status) };
    }),

  deleteAudioTrack: protectedProcedure
    .input(z.object({ id: idSchema }))
    .handler(async ({ input, context }) => {
      const track = await prisma.videoAudioTrack.findUnique({
        where: { id: input.id },
        include: { Video: { select: { ownerId: true } } },
      });
      if (!track) throw new ORPCError("NOT_FOUND");
      if (!isOwnerOrAdmin({ ownerId: track.Video.ownerId }, context)) {
        throw new ORPCError("NOT_FOUND");
      }
      if (track.isDefault) {
        throw new ORPCError("BAD_REQUEST", {
          message: "Cannot delete the default audio track; delete the video instead.",
        });
      }
      const { sourceKey, videoId, locale } = track;
      await prisma.videoAudioTrack.delete({ where: { id: track.id } });
      // Best-effort sweep of source and segment objects after the row is gone.
      if (sourceKey) {
        await deleteStorageObject(sourceKey).catch(() => {});
      }
      await deleteAudioTrackStorage(videoId, locale).catch(() => {});
      return { ok: true };
    }),

  // -------------------------------------------------------------------------
  // Subtitle tracks
  // -------------------------------------------------------------------------

  addSubtitleTrack: protectedProcedure
    .input(
      z.object({
        videoId: idSchema,
        locale: localeSchema,
        label: trackLabelSchema,
        kind: subtitleKindSchema.default("SUBTITLES"),
        isDefault: z.boolean().default(false),
        // Accept either WebVTT or SRT as plain text. The server validates and
        // converts SRT → VTT on the way in so storage stays single-format.
        content: z.string().min(1).max(2_000_000),
        format: z.enum(["vtt", "srt"]),
      }),
    )
    .handler(async ({ input, context }) => {
      const meta = await loadVideoMeta(input.videoId);
      if (!meta) throw new ORPCError("NOT_FOUND");
      if (!isOwnerOrAdmin(meta, context)) throw new ORPCError("NOT_FOUND");

      const vtt = input.format === "vtt" ? normalizeVtt(input.content) : srtToVtt(input.content);

      const storageKey = videoStorageKeys.subtitleTrackUpload(
        input.videoId,
        input.locale,
        input.kind,
        crypto.randomUUID(),
      );
      const { putStorageObject } = await import("../lib/storage");
      const subtitleIdentity = {
        videoId: input.videoId,
        locale: input.locale,
        kind: input.kind,
      };
      await putStorageObject(storageKey, new TextEncoder().encode(vtt), "text/vtt");

      let replacedStorageKey: string | null = null;
      try {
        const row = await prisma.$transaction(async (tx) => {
          const existing = await tx.videoSubtitleTrack.findUnique({
            where: { videoId_locale_kind: subtitleIdentity },
            select: { storageKey: true },
          });
          replacedStorageKey = existing?.storageKey ?? null;

          // Demote siblings in the same transaction as the upsert so concurrent
          // default changes cannot leave multiple defaults for one video/kind.
          if (input.isDefault) {
            await tx.videoSubtitleTrack.updateMany({
              where: { videoId: input.videoId, kind: input.kind },
              data: { isDefault: false },
            });
          }

          return tx.videoSubtitleTrack.upsert({
            where: {
              videoId_locale_kind: subtitleIdentity,
            },
            create: {
              videoId: input.videoId,
              locale: input.locale,
              label: input.label,
              kind: input.kind,
              isDefault: input.isDefault,
              storageKey,
            },
            update: {
              label: input.label,
              isDefault: input.isDefault,
              storageKey,
            },
          });
        });
        if (replacedStorageKey && replacedStorageKey !== storageKey) {
          await deleteStorageObject(replacedStorageKey).catch(() => {});
        }
        return { id: row.id };
      } catch (err) {
        await deleteStorageObject(storageKey).catch(() => {});
        throw err;
      }
    }),

  deleteSubtitleTrack: protectedProcedure
    .input(z.object({ id: idSchema }))
    .handler(async ({ input, context }) => {
      const track = await prisma.videoSubtitleTrack.findUnique({
        where: { id: input.id },
        include: { Video: { select: { ownerId: true } } },
      });
      if (!track) throw new ORPCError("NOT_FOUND");
      if (!isOwnerOrAdmin({ ownerId: track.Video.ownerId }, context)) {
        throw new ORPCError("NOT_FOUND");
      }
      await prisma.videoSubtitleTrack.delete({ where: { id: track.id } });
      await deleteStorageObject(track.storageKey).catch(() => {});
      return { ok: true };
    }),

  // -------------------------------------------------------------------------
  // Admin (cleanup / re-encode)
  // -------------------------------------------------------------------------

  adminReprocess: adminOr404Procedure
    .input(z.object({ id: idSchema }))
    .handler(async ({ input }) => {
      const meta = await loadVideoMeta(input.id);
      if (!meta) throw new ORPCError("NOT_FOUND");
      if (!meta.sourceKey) {
        throw new ORPCError("BAD_REQUEST", {
          message: "Original source has been deleted; re-upload required.",
        });
      }
      await prisma.video.update({
        where: { id: input.id },
        data: { status: "TRANSCODING", failureReason: null },
      });
      await transcodeVideoQueue.add("transcode-video", { videoId: input.id });
      return { ok: true };
    }),

  adminCleanupTrigger: adminOr404Procedure.handler(async () => {
    const job = await cleanupVideosQueue.add("cleanup-videos", { reason: "admin" });
    return { jobId: job.id };
  }),
};

// ---------------------------------------------------------------------------
// Storage cleanup helpers
// ---------------------------------------------------------------------------

async function deleteVideoStorage(videoId: string): Promise<void> {
  for (const prefix of [`videos/${videoId}/`, `rawVideos/${videoId}/`]) {
    for await (const obj of listStorageObjects(prefix)) {
      await deleteStorageObject(obj.key).catch(() => {});
    }
  }
}

async function deleteAudioTrackStorage(videoId: string, locale: string): Promise<void> {
  for await (const obj of listStorageObjects(`videos/${videoId}/a/${locale}/`)) {
    await deleteStorageObject(obj.key).catch(() => {});
  }
}

// ---------------------------------------------------------------------------
// SRT → VTT conversion
// ---------------------------------------------------------------------------

function normalizeVtt(input: string): string {
  if (input.trimStart().startsWith("WEBVTT")) return input;
  return `WEBVTT\n\n${input}`;
}

/**
 * Minimal SRT → WebVTT converter. Swaps comma decimal separators for periods
 * in cue timestamps and prepends the WebVTT signature. Doesn't handle
 * formatting tags ({\i1}, etc.) since they're rare and the player ignores
 * unknown content gracefully.
 */
function srtToVtt(srt: string): string {
  const body = srt
    .replace(/\r\n/g, "\n")
    .replace(/(\d{2}:\d{2}:\d{2}),(\d{3})/g, "$1.$2")
    .trim();
  return `WEBVTT\n\n${body}\n`;
}
