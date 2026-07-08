import { spawn, spawnSync } from "node:child_process";
import { createWriteStream } from "node:fs";
import { mkdir, readdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { pipeline } from "node:stream/promises";
import { getStorageObjectStream, putStorageObject } from "@flycockpit/api/lib/storage";
import { videoStorageKeys } from "@flycockpit/api/lib/videos";
import prisma from "@flycockpit/db";
import { env } from "@flycockpit/env/shared";
import type { TranscodeAudioTrackJobData } from "@flycockpit/queue";
import type { Job } from "bullmq";

/**
 * Encode an additional audio track (a dub) into HLS audio segments. The
 * source can be a pure audio file (.mp3/.wav/.m4a) or a video file we
 * extract audio from. Validates duration matches the canonical video within
 * ±2s before publishing; on mismatch flips the track to FAILED.
 *
 * Output: videos/<videoId>/a/<locale>/playlist.m3u8 + seg%03d.ts. The master
 * playlist is regenerated at request time and picks up the new track once
 * its status flips to READY.
 */

const SEGMENT_DURATION = 4;
const DURATION_TOLERANCE_SECONDS = 2;

export async function handleTranscodeAudioTrackJob(job: Job<TranscodeAudioTrackJobData>) {
  const { audioTrackId } = job.data;

  const track = await prisma.videoAudioTrack.findUnique({
    where: { id: audioTrackId },
    include: { Video: { select: { id: true, durationSeconds: true, status: true } } },
  });
  if (!track) {
    console.warn(`[transcode-audio-track] Job ${job.id}: audio track ${audioTrackId} not found`);
    return { skipped: true, audioTrackId };
  }
  if (!track.sourceKey) {
    await markFailed(audioTrackId, "Audio track has no source key");
    return { failed: true, audioTrackId };
  }
  if (track.Video.status !== "READY") {
    await markFailed(audioTrackId, "Parent video is not READY");
    return { failed: true, audioTrackId };
  }

  const workDir = await mkdir(join(tmpdir(), `aud-${audioTrackId}-${Date.now()}`), {
    recursive: true,
  });
  const tmp = workDir!;

  try {
    const sourcePath = join(tmp, "source");
    await downloadToFile(track.sourceKey, sourcePath);

    const sourceDuration = await ffprobeDuration(sourcePath);
    if (sourceDuration > env.VIDEO_TRANSCODE_MAX_DURATION_SECONDS) {
      await markFailed(
        audioTrackId,
        `Audio duration (${sourceDuration.toFixed(1)}s) exceeds the ${env.VIDEO_TRANSCODE_MAX_DURATION_SECONDS}s transcode limit.`,
      );
      return { failed: true, audioTrackId };
    }

    const videoDuration = track.Video.durationSeconds ?? 0;
    if (
      videoDuration > 0 &&
      Math.abs(sourceDuration - videoDuration) > DURATION_TOLERANCE_SECONDS
    ) {
      await markFailed(
        audioTrackId,
        `Audio duration (${sourceDuration.toFixed(1)}s) doesn't match video (${videoDuration.toFixed(1)}s). ` +
          "Frame-shifted dubs aren't supported — re-record matching the source cut, " +
          "or create a separate Video for the alternate edit.",
      );
      return { failed: true, audioTrackId };
    }

    const outDir = join(tmp, "out");
    await mkdir(outDir, { recursive: true });

    await runFfmpeg([
      "-y",
      "-i",
      sourcePath,
      "-vn",
      "-map",
      "0:a:0?",
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
      join(outDir, "seg%03d.ts"),
      join(outDir, "playlist.m3u8"),
    ]);

    // Upload to videos/<videoId>/a/<locale>/...
    const playlistKey = videoStorageKeys.audioTrackPlaylist(track.videoId, track.locale);
    const playlistBody = await readFile(join(outDir, "playlist.m3u8"));
    await putStorageObject(playlistKey, playlistBody, "application/vnd.apple.mpegurl");

    for (const file of await readdir(outDir)) {
      if (!file.endsWith(".ts")) continue;
      const key = videoStorageKeys.audioTrackSegment(track.videoId, track.locale, file);
      const body = await readFile(join(outDir, file));
      await putStorageObject(key, body, "video/mp2t");
    }

    await prisma.videoAudioTrack.update({
      where: { id: audioTrackId },
      data: { status: "READY", failureReason: null },
    });

    return { audioTrackId, locale: track.locale };
  } catch (err) {
    console.error(`[transcode-audio-track] Job ${job.id} failed:`, err);
    await markFailed(audioTrackId, err instanceof Error ? err.message : String(err));
    throw err;
  } finally {
    await rm(tmp, { recursive: true, force: true }).catch(() => {});
  }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

async function ffprobeDuration(path: string): Promise<number> {
  const result = spawnSync(
    env.VIDEO_FFPROBE_PATH,
    [
      "-v",
      "error",
      "-show_entries",
      "format=duration",
      "-of",
      "default=noprint_wrappers=1:nokey=1",
      path,
    ],
    { encoding: "utf8", timeout: 30_000, killSignal: "SIGKILL" },
  );
  if (result.status !== 0) {
    throw new Error(`ffprobe failed: ${result.stderr}`);
  }
  return Number.parseFloat(result.stdout.trim() || "0");
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
    const child = spawn(env.VIDEO_FFMPEG_PATH, boundedArgs, {
      stdio: ["ignore", "pipe", "pipe"],
    });
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

async function downloadToFile(key: string, dest: string): Promise<void> {
  const obj = await getStorageObjectStream(key);
  if (!obj) throw new Error(`Source object not found: ${key}`);
  await mkdir(dirname(dest), { recursive: true });
  await pipeline(obj.body, createWriteStream(dest));
}

async function markFailed(audioTrackId: string, reason: string): Promise<void> {
  await prisma.videoAudioTrack
    .update({
      where: { id: audioTrackId },
      data: { status: "FAILED", failureReason: reason.slice(0, 500) },
    })
    .catch(() => {});
}

export async function markTranscodeAudioTrackFailed(
  audioTrackId: string,
  reason: string,
): Promise<void> {
  await markFailed(audioTrackId, reason);
}
