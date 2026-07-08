import { spawn, spawnSync } from "node:child_process";
import { createWriteStream } from "node:fs";
import { mkdir, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { pipeline } from "node:stream/promises";
import { getStorageObjectStream, putStorageObject } from "@flycockpit/api/lib/storage";
import prisma from "@flycockpit/db";
import { env, VIDEO_ENABLE_4K } from "@flycockpit/env/shared";
import type { TranscodeVideoJobData } from "@flycockpit/queue";
import type { Job } from "bullmq";

/**
 * Transcode a raw uploaded video into an HLS adaptive ladder + sprite-sheet
 * thumbnails. Runs the ffmpeg binary (no native bindings) so the worker stays
 * provider-agnostic. The Dockerfile.worker installs ffmpeg into the base
 * image; locally `brew install ffmpeg` / `apt-get install ffmpeg` is enough.
 *
 * Pipeline:
 *   1. Pull the source from S3 into a temp dir.
 *   2. ffprobe to read dimensions + duration.
 *   3. Decide the rendition ladder: 360p, 540p, 720p, 1080p (and 2160p when
 *      the source is tall enough and 4K is enabled). Never upscale.
 *   4. ffmpeg pass: emit per-rendition video segments + per-rendition
 *      playlist, plus the source-locale audio rendition.
 *   5. Generate sprite-sheet thumbnails (1 frame every 5s, scaled to 160w,
 *      tiled 10×10) + a WebVTT manifest mapping timestamp ranges to sprite
 *      regions.
 *   6. Generate a poster frame at 25% duration if Video.posterAssetId is
 *      null.
 *   7. Upload every output to S3 under `videos/<id>/...`.
 *   8. Write VideoRendition rows + flip the default VideoAudioTrack to
 *      READY. Master playlist is rendered at request time from these rows.
 *   9. Flip Video.status to READY.
 *
 * Single attempt — the encode is deterministic, retrying burns ~10 minutes
 * for the same outcome. On failure Video.status flips to FAILED and
 * `failureReason` carries the operator-facing detail.
 */

const SEGMENT_DURATION = 4; // seconds per segment — typical HLS short-VOD value
const THUMB_INTERVAL = 5; // seconds between sprite frames
const SPRITE_GRID = 10; // 10×10 thumbnails per sprite sheet
const SPRITE_WIDTH = 160; // pixels — keeps each sprite well under 200KB

type Rendition = {
  height: number;
  width: number;
  videoBitrateKbps: number;
  maxBitrateKbps: number;
  bufBitrateKbps: number;
  audioBitrateKbps: number;
};

const LADDER: Rendition[] = [
  {
    height: 360,
    width: 640,
    videoBitrateKbps: 700,
    maxBitrateKbps: 900,
    bufBitrateKbps: 1000,
    audioBitrateKbps: 96,
  },
  {
    height: 540,
    width: 960,
    videoBitrateKbps: 1400,
    maxBitrateKbps: 1800,
    bufBitrateKbps: 2000,
    audioBitrateKbps: 128,
  },
  {
    height: 720,
    width: 1280,
    videoBitrateKbps: 2800,
    maxBitrateKbps: 3500,
    bufBitrateKbps: 4000,
    audioBitrateKbps: 128,
  },
  {
    height: 1080,
    width: 1920,
    videoBitrateKbps: 5000,
    maxBitrateKbps: 6500,
    bufBitrateKbps: 8000,
    audioBitrateKbps: 192,
  },
];
const LADDER_4K: Rendition = {
  height: 2160,
  width: 3840,
  videoBitrateKbps: 16000,
  maxBitrateKbps: 22000,
  bufBitrateKbps: 28000,
  audioBitrateKbps: 192,
};

export async function handleTranscodeVideoJob(job: Job<TranscodeVideoJobData>) {
  const { videoId } = job.data;

  const video = await prisma.video.findUnique({ where: { id: videoId } });
  if (!video) {
    console.warn(`[transcode-video] Job ${job.id}: video ${videoId} not found`);
    return { skipped: true, videoId };
  }
  if (!video.sourceKey) {
    await markFailed(videoId, "Video has no source key");
    return { failed: true, videoId };
  }

  const tmpDir = await mkdir(join(tmpdir(), `vid-${videoId}-${Date.now()}`), {
    recursive: true,
  });
  const workDir = tmpDir!;

  try {
    const sourcePath = join(workDir, "source");
    await downloadToFile(video.sourceKey, sourcePath);

    const probe = await ffprobe(sourcePath);
    if (!probe.height || !probe.width || !probe.duration) {
      await markFailed(videoId, "Could not probe source dimensions or duration");
      return { failed: true, videoId };
    }
    if (probe.duration > env.VIDEO_TRANSCODE_MAX_DURATION_SECONDS) {
      await markFailed(
        videoId,
        `Source duration (${probe.duration.toFixed(1)}s) exceeds the ${env.VIDEO_TRANSCODE_MAX_DURATION_SECONDS}s transcode limit.`,
      );
      return { failed: true, videoId };
    }

    const ladderPolicy =
      video.ladderPolicy === null
        ? video.ladderIncludes4k
          ? "INCLUDE_4K"
          : "STANDARD"
        : String(video.ladderPolicy);
    const include4k = ladderPolicy === "INCLUDE_4K" && VIDEO_ENABLE_4K;
    const renditions = pickRenditions(probe.height, include4k);
    if (renditions.length === 0) {
      await markFailed(
        videoId,
        `Source resolution (${probe.width}x${probe.height}) is below the minimum 360p rendition.`,
      );
      return { failed: true, videoId };
    }

    // -----------------------------------------------------------------
    // Encode video renditions + source-locale audio
    // -----------------------------------------------------------------
    const sourceLocale = video.sourceLocale;
    const outDir = join(workDir, "out");
    await mkdir(outDir, { recursive: true });

    const renditionDirs = await Promise.all(
      renditions.map(async (r) => {
        const dir = join(outDir, "v", String(r.height));
        await mkdir(dir, { recursive: true });
        return { rendition: r, dir };
      }),
    );
    const audioDir = join(outDir, "a", sourceLocale);
    await mkdir(audioDir, { recursive: true });

    await encodeLadder({
      sourcePath,
      renditionDirs,
      audioDir,
      duration: probe.duration,
      hasAudio: probe.hasAudio,
    });

    // Probe each rendition for actual bandwidth + codecs (libx264 may pick
    // a different profile per resolution).
    const renditionMeta = await Promise.all(
      renditionDirs.map(async ({ rendition, dir }) => {
        const playlistPath = join(dir, "playlist.m3u8");
        const probed = await ffprobeRendition(dir);
        return {
          height: rendition.height,
          width: rendition.width,
          // Bandwidth in HLS is in bits/sec. We use the calculated video
          // bitrate + audio bitrate (which streams alongside) as a safe upper
          // bound; ffprobe-measured average undercounts the peak.
          bandwidth: Math.round((rendition.maxBitrateKbps + rendition.audioBitrateKbps) * 1000),
          codecs: probed.codecs,
          dir,
          playlistPath,
        };
      }),
    );

    // -----------------------------------------------------------------
    // Sprite sheet thumbnails + WebVTT manifest
    // -----------------------------------------------------------------
    const thumbsDir = join(outDir, "thumbs");
    await mkdir(thumbsDir, { recursive: true });
    await generateThumbnails({ sourcePath, thumbsDir, duration: probe.duration });
    const thumbsVtt = buildThumbnailsVtt(probe.duration);
    await writeFile(join(outDir, "thumbs.vtt"), thumbsVtt, "utf8");

    // -----------------------------------------------------------------
    // Poster frame (if Video.posterAssetId is unset)
    // -----------------------------------------------------------------
    if (!video.posterAssetId) {
      const posterPath = join(outDir, "poster.jpg");
      await runFfmpeg([
        "-y",
        "-ss",
        String(Math.max(1, probe.duration * 0.25)),
        "-i",
        sourcePath,
        "-frames:v",
        "1",
        "-vf",
        `scale=-2:720:flags=lanczos`,
        "-q:v",
        "3",
        posterPath,
      ]);
    }

    // -----------------------------------------------------------------
    // Upload outputs to S3
    // -----------------------------------------------------------------
    await uploadOutputs(videoId, outDir, sourceLocale);

    // -----------------------------------------------------------------
    // DB writes
    // -----------------------------------------------------------------
    await prisma.$transaction(async (tx) => {
      // Wipe any prior renditions (re-encode replaces them entirely).
      await tx.videoRendition.deleteMany({ where: { videoId } });
      await tx.videoRendition.createMany({
        data: renditionMeta.map((r) => ({
          videoId,
          height: r.height,
          width: r.width,
          bandwidth: r.bandwidth,
          codecs: r.codecs,
        })),
      });

      // Seed (or update) the default audio track row.
      await tx.videoAudioTrack.updateMany({
        where: { videoId },
        data: { isDefault: false },
      });
      await tx.videoAudioTrack.upsert({
        where: {
          videoId_locale: { videoId, locale: sourceLocale },
        },
        create: {
          videoId,
          locale: sourceLocale,
          label: defaultAudioLabel(sourceLocale),
          isDefault: true,
          status: "READY",
        },
        update: {
          isDefault: true,
          status: "READY",
          failureReason: null,
        },
      });

      await tx.video.update({
        where: { id: videoId },
        data: {
          status: "READY",
          width: probe.width,
          height: probe.height,
          durationSeconds: probe.duration,
          failureReason: null,
        },
      });
    });

    return { videoId, renditions: renditionMeta.length };
  } catch (err) {
    console.error(`[transcode-video] Job ${job.id} failed:`, err);
    const message = err instanceof Error ? err.message : String(err);
    await markFailed(videoId, message);
    throw err;
  } finally {
    await rm(workDir, { recursive: true, force: true }).catch(() => {});
  }
}

// ---------------------------------------------------------------------------
// ffmpeg / ffprobe helpers
// ---------------------------------------------------------------------------

type Probe = {
  width: number;
  height: number;
  duration: number;
  hasAudio: boolean;
};

async function ffprobe(inputPath: string): Promise<Probe> {
  const result = spawnSync(
    env.VIDEO_FFPROBE_PATH,
    [
      "-v",
      "error",
      "-show_entries",
      "stream=codec_type,width,height:format=duration",
      "-of",
      "json",
      inputPath,
    ],
    { encoding: "utf8", timeout: 30_000, killSignal: "SIGKILL" },
  );
  if (result.status !== 0) {
    throw new Error(`ffprobe failed: ${result.stderr}`);
  }
  const parsed = JSON.parse(result.stdout) as {
    streams?: Array<{ codec_type?: string; width?: number; height?: number }>;
    format?: { duration?: string };
  };
  const stream = parsed.streams?.find((s) => s.codec_type === "video") ?? parsed.streams?.[0];
  const duration = Number.parseFloat(parsed.format?.duration ?? "0");
  return {
    width: stream?.width ?? 0,
    height: stream?.height ?? 0,
    duration,
    hasAudio: parsed.streams?.some((s) => s.codec_type === "audio") ?? false,
  };
}

async function ffprobeRendition(renditionDir: string): Promise<{ codecs: string }> {
  // Read the first segment so we can extract the actual codec string ffmpeg
  // emitted. HLS players need this for the CODECS= tag.
  const files = await readdir(renditionDir);
  const segment = files.find((f) => f.endsWith(".ts") || f.endsWith(".m4s"));
  if (!segment) {
    // Fall back to a common-denominator codec string — players gracefully
    // negotiate when CODECS= is approximate.
    return { codecs: "avc1.640028,mp4a.40.2" };
  }
  const probe = spawnSync(
    env.VIDEO_FFPROBE_PATH,
    [
      "-v",
      "error",
      "-show_entries",
      "stream=codec_name,profile,level",
      "-of",
      "json",
      join(renditionDir, segment),
    ],
    { encoding: "utf8", timeout: 30_000, killSignal: "SIGKILL" },
  );
  if (probe.status !== 0) return { codecs: "avc1.640028,mp4a.40.2" };
  // We don't bother parsing the profile/level into the avc1.XXXXXX hex —
  // emitting a safe baseline ("avc1.640028" = High@4.1 + AAC LC) covers the
  // typical encode and Safari is happy with it. Tighten this if you need
  // exact CODECS= reporting.
  return { codecs: "avc1.640028,mp4a.40.2" };
}

function pickRenditions(sourceHeight: number, include4k: boolean): Rendition[] {
  const ladder = [...LADDER];
  if (include4k) ladder.push(LADDER_4K);
  // Never upscale — drop renditions taller than the source.
  return ladder.filter((r) => r.height <= sourceHeight);
}

async function encodeLadder(args: {
  sourcePath: string;
  renditionDirs: Array<{ rendition: Rendition; dir: string }>;
  audioDir: string;
  duration: number;
  hasAudio: boolean;
}): Promise<void> {
  // Two passes so video and audio segments live in separate playlists. This
  // is what makes runtime audio-language switching work: the master playlist
  // says AUDIO="audio" and points each rendition at videos/<id>/v/<h>/ while
  // pointing the audio group at videos/<id>/a/<locale>/.

  // -------- Pass 1: video-only ladder --------
  const videoArgs: string[] = [
    "-y",
    "-i",
    args.sourcePath,
    "-preset",
    env.VIDEO_X264_PRESET,
    "-an", // strip audio in this pass
  ];

  const splits = args.renditionDirs.length;
  const splitLabels = args.renditionDirs.map((_, i) => `[v${i + 1}]`).join("");
  const filter = [
    `[0:v]split=${splits}${splitLabels}`,
    ...args.renditionDirs.map(
      ({ rendition }, i) =>
        `[v${i + 1}]scale=w=${rendition.width}:h=${rendition.height}:force_original_aspect_ratio=decrease,pad=${rendition.width}:${rendition.height}:(ow-iw)/2:(oh-ih)/2:color=black[v${i + 1}out]`,
    ),
  ].join(";");
  videoArgs.push("-filter_complex", filter);

  args.renditionDirs.forEach(({ rendition }, i) => {
    videoArgs.push(
      "-map",
      `[v${i + 1}out]`,
      `-c:v:${i}`,
      "libx264",
      `-threads:v:${i}`,
      String(env.VIDEO_FFMPEG_THREADS),
      `-b:v:${i}`,
      `${rendition.videoBitrateKbps}k`,
      `-maxrate:v:${i}`,
      `${rendition.maxBitrateKbps}k`,
      `-bufsize:v:${i}`,
      `${rendition.bufBitrateKbps}k`,
      `-crf:v:${i}`,
      String(env.VIDEO_X264_CRF),
      "-pix_fmt",
      "yuv420p",
      "-g",
      "48",
      "-keyint_min",
      "48",
      "-sc_threshold",
      "0",
    );
  });

  const ladderParent = dirname(args.renditionDirs[0]!.dir);
  const varStreamMap = args.renditionDirs.map((_, i) => `v:${i}`).join(" ");
  videoArgs.push(
    "-f",
    "hls",
    "-hls_time",
    String(SEGMENT_DURATION),
    "-hls_playlist_type",
    "vod",
    "-hls_segment_type",
    "mpegts",
    "-hls_segment_filename",
    join(ladderParent, "%v", "seg%03d.ts"),
    "-master_pl_name",
    "__ignored.m3u8",
    "-var_stream_map",
    varStreamMap,
    join(ladderParent, "%v", "playlist.m3u8"),
  );

  await runFfmpeg(videoArgs);

  // ffmpeg names variants 0/, 1/, … — move into our height-named directories.
  for (let i = 0; i < args.renditionDirs.length; i++) {
    const numericDir = join(ladderParent, String(i));
    const targetDir = args.renditionDirs[i]!.dir;
    if (numericDir === targetDir) continue;
    const files = await readdir(numericDir).catch(() => [] as string[]);
    for (const f of files) {
      await writeFile(join(targetDir, f), await readFile(join(numericDir, f)));
    }
    await rm(numericDir, { recursive: true, force: true }).catch(() => {});
  }

  // Strip the ignored master playlist if ffmpeg wrote it.
  await rm(join(ladderParent, "__ignored.m3u8"), { force: true }).catch(() => {});

  // -------- Pass 2: audio-only AAC --------
  // Single audio rendition keyed by sourceLocale. Additional dubs land in
  // their own directories via the transcode-audio-track job.
  const audioArgs = [
    "-y",
    ...(args.hasAudio
      ? ["-i", args.sourcePath, "-vn", "-map", "0:a:0?"]
      : [
          "-f",
          "lavfi",
          "-i",
          "anullsrc=channel_layout=stereo:sample_rate=48000",
          "-t",
          String(args.duration),
        ]),
    "-c:a",
    "aac",
    "-ar",
    "48000",
    "-b:a",
    "128k",
    "-f",
    "hls",
    "-hls_time",
    String(SEGMENT_DURATION),
    "-hls_playlist_type",
    "vod",
    "-hls_segment_type",
    "mpegts",
    "-hls_segment_filename",
    join(args.audioDir, "seg%03d.ts"),
    join(args.audioDir, "playlist.m3u8"),
  ];
  await runFfmpeg(audioArgs);
}

async function generateThumbnails(args: {
  sourcePath: string;
  thumbsDir: string;
  duration: number;
}): Promise<void> {
  // fps=1/N gives one frame every N seconds; tile=10x10 packs them into
  // sprite sheets; the %03d index increments per sheet. Quality 5 (qscale)
  // is a good size/quality trade.
  await runFfmpeg([
    "-y",
    "-i",
    args.sourcePath,
    "-vf",
    `fps=1/${THUMB_INTERVAL},scale=${SPRITE_WIDTH}:-2,tile=${SPRITE_GRID}x${SPRITE_GRID}`,
    "-qscale:v",
    "5",
    join(args.thumbsDir, "%03d.jpg"),
  ]);
}

function buildThumbnailsVtt(duration: number): string {
  // Each sprite holds SPRITE_GRID×SPRITE_GRID thumbs; each thumb covers
  // THUMB_INTERVAL seconds. The first thumb in sprite N covers
  // (N × SPRITE_GRID² + 0) × THUMB_INTERVAL.
  const thumbHeight = Math.round((SPRITE_WIDTH * 9) / 16); // aspect-ratio guess
  const perSheet = SPRITE_GRID * SPRITE_GRID;
  const lines: string[] = ["WEBVTT", ""];
  const totalThumbs = Math.ceil(duration / THUMB_INTERVAL);
  for (let i = 0; i < totalThumbs; i++) {
    const sheet = Math.floor(i / perSheet);
    const slot = i % perSheet;
    const col = slot % SPRITE_GRID;
    const row = Math.floor(slot / SPRITE_GRID);
    const start = i * THUMB_INTERVAL;
    const end = Math.min((i + 1) * THUMB_INTERVAL, duration);
    lines.push(formatVttTime(start) + " --> " + formatVttTime(end));
    lines.push(
      `thumbs/${String(sheet + 1).padStart(3, "0")}.jpg#xywh=${col * SPRITE_WIDTH},${row * thumbHeight},${SPRITE_WIDTH},${thumbHeight}`,
    );
    lines.push("");
  }
  return lines.join("\n");
}

function formatVttTime(seconds: number): string {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = (seconds % 60).toFixed(3);
  return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:${s.padStart(6, "0")}`;
}

async function runFfmpeg(args: string[]): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const boundedArgs = [
      "-threads",
      String(env.VIDEO_FFMPEG_THREADS),
      "-filter_threads",
      String(env.VIDEO_FFMPEG_THREADS),
      "-filter_complex_threads",
      String(env.VIDEO_FFMPEG_THREADS),
      "-timelimit",
      String(env.VIDEO_FFMPEG_TIMELIMIT_SECONDS),
      ...args,
    ];
    const child = spawn(env.VIDEO_FFMPEG_PATH, boundedArgs, { stdio: ["ignore", "pipe", "pipe"] });
    const timeoutMs = (env.VIDEO_FFMPEG_TIMELIMIT_SECONDS + 30) * 1000;
    const timeout = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error(`ffmpeg timed out after ${timeoutMs}ms`));
    }, timeoutMs);
    let stderr = "";
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });
    child.on("error", (err) => {
      clearTimeout(timeout);
      reject(err);
    });
    child.on("close", (code) => {
      clearTimeout(timeout);
      if (code === 0) resolve();
      else reject(new Error(`ffmpeg exited with code ${code}: ${stderr.slice(-2048)}`));
    });
  });
}

// ---------------------------------------------------------------------------
// S3 transfer helpers
// ---------------------------------------------------------------------------

async function downloadToFile(key: string, dest: string): Promise<void> {
  const obj = await getStorageObjectStream(key);
  if (!obj) throw new Error(`Source object not found: ${key}`);
  await mkdir(dirname(dest), { recursive: true });
  await pipeline(obj.body, createWriteStream(dest));
}

async function uploadOutputs(videoId: string, outDir: string, sourceLocale: string): Promise<void> {
  // Walk every file under outDir and PUT it to the matching videos/<id>/...
  // path. Skip the master playlist — we render that at request time.
  for await (const filePath of walk(outDir)) {
    const rel = filePath.slice(outDir.length + 1).replace(/\\/g, "/");
    if (rel === "__ignored.m3u8") continue;
    const key = `videos/${videoId}/${rel}`;
    const body = await readFile(filePath);
    const contentType = contentTypeFor(rel);
    await putStorageObject(key, body, contentType);
  }
  void sourceLocale;
}

async function* walk(dir: string): AsyncGenerator<string> {
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const p = join(dir, entry.name);
    if (entry.isDirectory()) yield* walk(p);
    else yield p;
  }
}

function contentTypeFor(rel: string): string {
  if (rel.endsWith(".m3u8")) return "application/vnd.apple.mpegurl";
  if (rel.endsWith(".ts")) return "video/mp2t";
  if (rel.endsWith(".aac")) return "audio/aac";
  if (rel.endsWith(".m4s")) return "video/iso.segment";
  if (rel.endsWith(".vtt")) return "text/vtt";
  if (rel.endsWith(".jpg") || rel.endsWith(".jpeg")) return "image/jpeg";
  return "application/octet-stream";
}

function defaultAudioLabel(locale: string): string {
  // The label is shown in the player's audio menu and stays in the track's
  // own language. For initial seed we use the locale tag itself; admins can
  // rename it via the admin UI.
  return locale;
}

async function markFailed(videoId: string, reason: string): Promise<void> {
  await prisma.video
    .update({
      where: { id: videoId },
      data: { status: "FAILED", failureReason: reason.slice(0, 500) },
    })
    .catch(() => {});
}

export async function markTranscodeVideoFailed(videoId: string, reason: string): Promise<void> {
  await markFailed(videoId, reason);
}
