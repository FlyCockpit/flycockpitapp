import { storage } from "@flycockpit/api/lib/storage";
import {
  authorizeVideoRead,
  buildMasterPlaylist,
  playlistCacheControl,
  readVideoArtifact,
  VideoError,
  type VideoMeta,
  type VideoSubtitleKind,
  type Viewer,
  videoCacheControl,
  videoStorageKeys,
} from "@flycockpit/api/lib/videos";
import type { Session } from "@flycockpit/auth";
import prisma from "@flycockpit/db";
import type { Env, Hono } from "hono";

/**
 * Video pattern HTTP routes — playlist + segment + audio + subtitle + thumbnail
 * delivery. Uploads are driven by oRPC procedures (see videos router) which
 * delegate to `startVideoUpload` / `presignVideoUploadParts` / `completeVideoUpload`
 * in `@flycockpit/api/lib/videos`.
 *
 * The single permission boundary is `authorizeVideoRead()` — every artifact
 * route resolves the Video, runs `canViewVideo`, then proxies bytes from S3.
 *
 *   GET /api/videos/:videoId/playlist.m3u8                — master playlist
 *   GET /api/videos/:videoId/v/:height/playlist.m3u8      — rendition playlist
 *   GET /api/videos/:videoId/v/:height/:segment           — video segment
 *   GET /api/videos/:videoId/a/:locale/playlist.m3u8      — audio rendition
 *   GET /api/videos/:videoId/a/:locale/:segment           — audio segment
 *   GET /api/videos/:videoId/t/:locale.:kind.vtt          — subtitle track
 *   GET /api/videos/:videoId/thumbs.vtt                   — hover thumbnails
 *   GET /api/videos/:videoId/thumbs/:sprite               — sprite-sheet JPEG
 *   GET /api/videos/:videoId/poster                       — generated poster
 *
 * HLS is a many-small-files protocol — every segment GET re-authorizes via
 * `authorizeVideoRead`. That sounds expensive, but the Video row is small
 * (~1KB) and Postgres serves it in well under a millisecond. We trade that
 * for the right thing: a PUBLIC→RESTRICTED flip is honored on the next
 * segment request, not 24 hours later. CDN caching (when configured) is
 * separately enforced by the Cache-Control header.
 */

type SessionEnv = { Variables: { session: Session | null } };

const SEGMENT_NAME_PATTERN = /^[A-Za-z0-9_.-]+\.(ts|m4s|aac|mp4)$/;
const SPRITE_NAME_PATTERN = /^\d{3}\.jpg$/;
const VTT_NAME_PATTERN = /^([A-Za-z0-9-]{2,10})\.(subtitles|captions|descriptions)\.vtt$/;

export function mountVideoRoutes<E extends Env & SessionEnv>(app: Hono<E>): Hono<E> {
  app.get("/api/videos/:videoId/playlist.m3u8", async (c) => {
    if (!storage) return storageDisabled();
    const viewer = viewerFromSession(c.get("session"));
    try {
      const meta = await authorizeVideoRead(c.req.param("videoId"), viewer);
      if (meta.status !== "READY") {
        return jsonResponse({ error: "Video is still processing. Try again in a moment." }, 409);
      }
      const [renditions, audioTracks, subtitleTracks] = await Promise.all([
        prisma.videoRendition.findMany({
          where: { videoId: meta.id },
          orderBy: { height: "asc" },
        }),
        prisma.videoAudioTrack.findMany({
          where: { videoId: meta.id, status: "READY" },
          orderBy: { createdAt: "asc" },
        }),
        prisma.videoSubtitleTrack.findMany({
          where: { videoId: meta.id },
          orderBy: { createdAt: "asc" },
        }),
      ]);

      if (renditions.length === 0 || audioTracks.length === 0) {
        return jsonResponse({ error: "Video is still processing. Try again in a moment." }, 409);
      }

      const body = buildMasterPlaylist({
        video: meta,
        renditions: renditions.map((r) => ({
          height: r.height,
          width: r.width,
          bandwidth: r.bandwidth,
          codecs: r.codecs,
        })),
        audioTracks: audioTracks.map((a) => ({
          locale: a.locale,
          label: a.label,
          isDefault: a.isDefault,
        })),
        subtitleTracks: subtitleTracks.map((s) => ({
          locale: s.locale,
          label: s.label,
          kind: String(s.kind) as VideoSubtitleKind,
          isDefault: s.isDefault,
        })),
      });
      return playlistResponse(body, meta);
    } catch (err) {
      return videoErrorResponse(err);
    }
  });

  app.get("/api/videos/:videoId/v/:height/playlist.m3u8", async (c) => {
    if (!storage) return storageDisabled();
    const viewer = viewerFromSession(c.get("session"));
    const height = Number.parseInt(c.req.param("height"), 10);
    if (!Number.isFinite(height) || height <= 0) {
      return jsonResponse({ error: "Invalid rendition" }, 400);
    }
    try {
      const meta = await authorizeVideoRead(c.req.param("videoId"), viewer);
      const key = videoStorageKeys.videoRenditionPlaylist(meta.id, height);
      return streamArtifact(c.req.header("range") ?? null, key, meta, "playlist");
    } catch (err) {
      return videoErrorResponse(err);
    }
  });

  app.get("/api/videos/:videoId/v/:height/:segment", async (c) => {
    if (!storage) return storageDisabled();
    const viewer = viewerFromSession(c.get("session"));
    const height = Number.parseInt(c.req.param("height"), 10);
    const segment = c.req.param("segment");
    if (!Number.isFinite(height) || !SEGMENT_NAME_PATTERN.test(segment)) {
      return jsonResponse({ error: "Invalid segment" }, 400);
    }
    try {
      const meta = await authorizeVideoRead(c.req.param("videoId"), viewer);
      const key = videoStorageKeys.videoRenditionSegment(meta.id, height, segment);
      return streamArtifact(c.req.header("range") ?? null, key, meta, "segment");
    } catch (err) {
      return videoErrorResponse(err);
    }
  });

  app.get("/api/videos/:videoId/a/:locale/playlist.m3u8", async (c) => {
    if (!storage) return storageDisabled();
    const viewer = viewerFromSession(c.get("session"));
    const locale = c.req.param("locale");
    if (!isSafeLocale(locale)) {
      return jsonResponse({ error: "Invalid locale" }, 400);
    }
    try {
      const meta = await authorizeVideoRead(c.req.param("videoId"), viewer);
      const key = videoStorageKeys.audioTrackPlaylist(meta.id, locale);
      return streamArtifact(c.req.header("range") ?? null, key, meta, "playlist");
    } catch (err) {
      return videoErrorResponse(err);
    }
  });

  app.get("/api/videos/:videoId/a/:locale/:segment", async (c) => {
    if (!storage) return storageDisabled();
    const viewer = viewerFromSession(c.get("session"));
    const locale = c.req.param("locale");
    const segment = c.req.param("segment");
    if (!isSafeLocale(locale) || !SEGMENT_NAME_PATTERN.test(segment)) {
      return jsonResponse({ error: "Invalid segment" }, 400);
    }
    try {
      const meta = await authorizeVideoRead(c.req.param("videoId"), viewer);
      const key = videoStorageKeys.audioTrackSegment(meta.id, locale, segment);
      return streamArtifact(c.req.header("range") ?? null, key, meta, "segment");
    } catch (err) {
      return videoErrorResponse(err);
    }
  });

  app.get("/api/videos/:videoId/t/:filename", async (c) => {
    if (!storage) return storageDisabled();
    const viewer = viewerFromSession(c.get("session"));
    const filename = c.req.param("filename");
    const subtitle = parseSubtitleFilename(filename);
    if (!subtitle) {
      return jsonResponse({ error: "Invalid subtitle file" }, 400);
    }
    try {
      const meta = await authorizeVideoRead(c.req.param("videoId"), viewer);
      const track = await prisma.videoSubtitleTrack.findUnique({
        where: {
          videoId_locale_kind: {
            videoId: meta.id,
            locale: subtitle.locale,
            kind: subtitle.kind,
          },
        },
        select: { storageKey: true },
      });
      if (!track) throw new VideoError("NOT_FOUND", "Subtitle track not found");
      return streamArtifact(c.req.header("range") ?? null, track.storageKey, meta, "subtitle");
    } catch (err) {
      return videoErrorResponse(err);
    }
  });

  app.get("/api/videos/:videoId/thumbs.vtt", async (c) => {
    if (!storage) return storageDisabled();
    const viewer = viewerFromSession(c.get("session"));
    try {
      const meta = await authorizeVideoRead(c.req.param("videoId"), viewer);
      const key = videoStorageKeys.thumbnailsVtt(meta.id);
      return streamArtifact(c.req.header("range") ?? null, key, meta, "subtitle");
    } catch (err) {
      return videoErrorResponse(err);
    }
  });

  app.get("/api/videos/:videoId/thumbs/:sprite", async (c) => {
    if (!storage) return storageDisabled();
    const viewer = viewerFromSession(c.get("session"));
    const sprite = c.req.param("sprite");
    if (!SPRITE_NAME_PATTERN.test(sprite)) {
      return jsonResponse({ error: "Invalid sprite" }, 400);
    }
    try {
      const meta = await authorizeVideoRead(c.req.param("videoId"), viewer);
      const key = `videos/${meta.id}/thumbs/${sprite}`;
      return streamArtifact(c.req.header("range") ?? null, key, meta, "image");
    } catch (err) {
      return videoErrorResponse(err);
    }
  });

  app.get("/api/videos/:videoId/poster", async (c) => {
    if (!storage) return storageDisabled();
    const viewer = viewerFromSession(c.get("session"));
    try {
      const meta = await authorizeVideoRead(c.req.param("videoId"), viewer);
      const key = videoStorageKeys.poster(meta.id);
      return streamArtifact(c.req.header("range") ?? null, key, meta, "image");
    } catch (err) {
      return videoErrorResponse(err);
    }
  });

  return app;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function streamArtifact(
  range: string | null,
  key: string,
  meta: VideoMeta,
  kind: "playlist" | "segment" | "subtitle" | "image",
): Promise<Response> {
  const result = await readVideoArtifact(key, range);
  if (!result) {
    return jsonResponse({ error: "Not found" }, 404);
  }
  const contentType = result.contentType ?? inferContentType(kind, key);
  const cache =
    kind === "playlist"
      ? playlistCacheControl(meta.visibility)
      : videoCacheControl(meta.visibility);
  const headers: Record<string, string> = {
    "Content-Type": contentType,
    "Cache-Control": cache,
    "Accept-Ranges": "bytes",
  };
  if (result.contentLength !== null) {
    headers["Content-Length"] = String(result.contentLength);
  }
  if (result.contentRange) {
    headers["Content-Range"] = result.contentRange;
    return new Response(result.body, { status: 206, headers });
  }
  return new Response(result.body, { status: 200, headers });
}

function inferContentType(
  kind: "playlist" | "segment" | "subtitle" | "image",
  key: string,
): string {
  if (kind === "playlist") return "application/vnd.apple.mpegurl";
  if (kind === "subtitle") return "text/vtt";
  if (kind === "image") return "image/jpeg";
  if (key.endsWith(".aac")) return "audio/aac";
  if (key.endsWith(".m4s")) return "video/iso.segment";
  if (key.endsWith(".mp4")) return "video/mp4";
  return "video/mp2t"; // .ts
}

function playlistResponse(body: string, meta: VideoMeta): Response {
  return new Response(body, {
    status: 200,
    headers: {
      "Content-Type": "application/vnd.apple.mpegurl",
      "Cache-Control": playlistCacheControl(meta.visibility),
    },
  });
}

function viewerFromSession(session: Session | null | undefined): Viewer {
  if (!session?.user) return { kind: "anonymous" };
  return { kind: "user", userId: session.user.id, role: session.user.role ?? "user" };
}

function isSafeLocale(locale: string): boolean {
  return /^[A-Za-z0-9-]{2,10}$/.test(locale);
}

function parseSubtitleFilename(
  filename: string,
): { locale: string; kind: VideoSubtitleKind } | null {
  const match = VTT_NAME_PATTERN.exec(filename);
  if (!match) return null;
  const kind = match[2]?.toUpperCase();
  if (kind !== "SUBTITLES" && kind !== "CAPTIONS" && kind !== "DESCRIPTIONS") return null;
  return { locale: match[1]!, kind };
}

function storageDisabled(): Response {
  return jsonResponse(
    { error: "Video hosting is temporarily unavailable. Try again shortly." },
    503,
  );
}

function jsonResponse(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function videoErrorResponse(err: unknown): Response {
  if (err instanceof VideoError) {
    if (err.code === "STORAGE_DISABLED") return storageDisabled();
    if (err.code === "GONE") {
      return jsonResponse({ error: "That video was deleted or is no longer available." }, 410);
    }
    if (err.code === "UPLOAD_MISSING") {
      return jsonResponse({ error: "Video storage state is inconsistent. Contact an admin." }, 409);
    }
    if (err.code === "INVALID_STATE") {
      return jsonResponse({ error: "Video is not ready for this operation." }, 409);
    }
    // 404 for both NOT_FOUND and FORBIDDEN — don't leak existence.
    return jsonResponse({ error: "Not found" }, 404);
  }
  console.error("[video-routes] Unexpected error:", err);
  return jsonResponse({ error: "Something didn't work on our end. Try again in a moment." }, 500);
}
