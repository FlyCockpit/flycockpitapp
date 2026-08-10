import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
export type MediaRuntimePair = Readonly<{ ffmpeg: string; ffprobe: string }>;
type VersionProbe = (program: string) => Promise<string>;

const defaultProbe: VersionProbe = async (program) => {
  const { stdout, stderr } = await execFileAsync(program, ["-version"], {
    timeout: 30_000,
    maxBuffer: 64 * 1024,
  });
  return `${stdout}\n${stderr}`;
};

function releaseMajor(evidence: string): number | undefined {
  const match = evidence.match(/\b(?:ffmpeg|ffprobe) version\s+(\d+)(?:\.|\s)/i);
  return match?.[1] === undefined ? undefined : Number.parseInt(match[1], 10);
}

/** Enforces cockpit-core's `ffmpeg-ffprobe-compatible-pair` catalog rule. */
export async function resolveMediaRuntimePair(
  pair: MediaRuntimePair,
  probe: VersionProbe = defaultProbe,
): Promise<MediaRuntimePair> {
  const [ffmpegEvidence, ffprobeEvidence] = await Promise.all([
    probe(pair.ffmpeg),
    probe(pair.ffprobe),
  ]);
  const ffmpegMajor = releaseMajor(ffmpegEvidence);
  const ffprobeMajor = releaseMajor(ffprobeEvidence);
  if (ffmpegMajor === undefined || ffprobeMajor === undefined || ffmpegMajor !== ffprobeMajor) {
    throw new Error(
      "media inspection requires a healthy compatible FFmpeg/FFprobe pair (matching release majors)",
    );
  }
  return Object.freeze({ ...pair });
}

let resolvedPair: Promise<MediaRuntimePair> | undefined;
export function mediaRuntimePair(configuredPair: MediaRuntimePair): Promise<MediaRuntimePair> {
  resolvedPair ??= resolveMediaRuntimePair(configuredPair);
  return resolvedPair;
}
