/**
 * Client-side multipart upload helpers. Mirrors the asset uploadAsset()
 * shape — a single function that drives the full presign / PUT / finalize
 * round trip — but uses S3 multipart upload so the client can retry an
 * individual part instead of the whole file when the network blips.
 *
 * Use inside a TanStack Query mutation:
 *
 *   const upload = useMutation({
 *     mutationFn: (file: File) => uploadVideo({
 *       file,
 *       title: "My talk",
 *       sourceLocale: "en-US",
 *       onProgress: (p) => setProgress(p),
 *       rpc: orpc.videos,
 *     }),
 *     onSuccess: ({ videoId }) => { navigate(`/admin/videos/${videoId}`) },
 *   });
 *
 * Audio dubs share the same loop via `uploadAudioTrack()` — both call into
 * the generic `uploadMultipart()` helper below.
 *
 * The upload is driven via oRPC (POST /rpc/videos/*) so it inherits CORS +
 * CSRF + rate limiting from the rest of the API. Bytes never stream through
 * the app server — every part PUTs directly to S3.
 */

export type UploadVideoOptions = {
  file: File;
  title: string;
  description?: string | null;
  visibility?: "PUBLIC" | "RESTRICTED";
  sourceLocale: string;
  ladderPolicy?: "STANDARD" | "INCLUDE_4K";
  onProgress?: (progress: number) => void;
  signal?: AbortSignal;
  /**
   * oRPC client. Pass the same `orpc` instance you use elsewhere in the app
   * so the upload reuses the auth + CSRF + base URL configuration. The
   * helper deliberately doesn't construct its own client to keep this file
   * agnostic to how the app wires oRPC.
   */
  rpc: VideoRpcInterface;
};

export type UploadVideoResult = {
  videoId: string;
};

export type UploadAudioTrackOptions = {
  videoId: string;
  locale: string;
  label: string;
  file: File;
  onProgress?: (progress: number) => void;
  signal?: AbortSignal;
  /** Same shape rule as `uploadVideo()` — pass the app's shared oRPC client. */
  rpc: AudioTrackRpcInterface;
};

export type UploadAudioTrackResult = {
  audioTrackId: string;
};

/**
 * Minimal interface of the oRPC `videos` router methods this helper needs.
 * Typed structurally so the helper compiles without importing the full
 * AppRouterClient type (which would drag the server bundle into the client).
 */
export interface VideoRpcInterface {
  start: (input: {
    title: string;
    description: string | null;
    visibility: "PUBLIC" | "RESTRICTED";
    sourceLocale: string;
    sourceMimeType: string;
    sourceSize: number;
    ladderPolicy: "STANDARD" | "INCLUDE_4K";
  }) => Promise<{ videoId: string; uploadId: string; storageKey: string }>;
  presignParts: (input: {
    videoId: string;
    uploadId: string;
    partNumbers: number[];
  }) => Promise<{ parts: Array<{ url: string; partNumber: number; expiresIn: number }> }>;
  complete: (input: {
    videoId: string;
    uploadId: string;
    parts: Array<{ partNumber: number; etag: string }>;
  }) => Promise<unknown>;
  abort: (input: { videoId: string; uploadId: string }) => Promise<unknown>;
  heartbeat: (input: { videoId: string }) => Promise<unknown>;
}

/**
 * Structural shape of the audio-track oRPC procedures consumed by
 * `uploadAudioTrack()`. Mirrors `VideoRpcInterface` but for the
 * `videoAudioTrack.*` flow.
 */
export interface AudioTrackRpcInterface {
  startAudioTrack: (input: {
    videoId: string;
    locale: string;
    label: string;
    mimeType: string;
    size: number;
  }) => Promise<{ audioTrackId: string; uploadId: string; storageKey: string }>;
  presignAudioTrackParts: (input: {
    audioTrackId: string;
    uploadId: string;
    partNumbers: number[];
  }) => Promise<{ parts: Array<{ url: string; partNumber: number; expiresIn?: number }> }>;
  finalizeAudioTrack: (input: {
    audioTrackId: string;
    uploadId: string;
    parts: Array<{ partNumber: number; etag: string }>;
  }) => Promise<unknown>;
  abortAudioTrack: (input: { audioTrackId: string; uploadId: string }) => Promise<unknown>;
  heartbeatAudioTrack: (input: { audioTrackId: string }) => Promise<unknown>;
}

/**
 * Generic multipart-upload protocol. The caller pre-binds whatever IDs each
 * variant needs (videoId, audioTrackId, uploadId) by closing over them when
 * constructing the protocol object. The loop never has to know the shape
 * of those identifiers.
 */
export interface MultipartProtocol {
  presignParts: (input: {
    partNumbers: number[];
  }) => Promise<{ parts: Array<{ url: string; partNumber: number; expiresIn?: number }> }>;
  complete: (input: { parts: Array<{ partNumber: number; etag: string }> }) => Promise<unknown>;
  /** Called best-effort on failure. */
  abort: () => Promise<unknown>;
  /** Called on a fixed interval while the upload is in flight. */
  heartbeat: () => Promise<unknown>;
}

export type UploadMultipartOptions = {
  file: File;
  protocol: MultipartProtocol;
  onProgress?: (progress: number) => void;
  signal?: AbortSignal;
  /** Defaults to PART_CONCURRENCY (4). */
  concurrency?: number;
};

// 8 MB per part. S3 requires parts to be >= 5 MB (except the last one) and
// the maximum is 10,000 parts. 8 MB × 10,000 = 80 GB — well under our
// VIDEO_UPLOAD_MAX_BYTES default of 10 GB. Larger files can be supported by
// bumping this constant.
const PART_SIZE = 8 * 1024 * 1024;
// Upload up to this many parts concurrently. 4 saturates a typical 100 Mbps
// uplink without overwhelming the browser's per-host connection limit.
const PART_CONCURRENCY = 4;
// Server batches presign generation in groups of this size; matched to
// the oRPC procedure's `.max(50)` cap on partNumbers.
const PRESIGN_BATCH = 25;
const HEARTBEAT_INTERVAL_MS = 60_000;

export async function uploadVideo(opts: UploadVideoOptions): Promise<UploadVideoResult> {
  const {
    file,
    title,
    description = null,
    visibility = "RESTRICTED",
    sourceLocale,
    ladderPolicy = "STANDARD",
    onProgress,
    signal,
    rpc,
  } = opts;

  const totalParts = Math.max(1, Math.ceil(file.size / PART_SIZE));
  if (totalParts > 10_000) {
    throw new Error("File exceeds the S3 multipart 10,000-part limit. Pick a larger PART_SIZE.");
  }

  const upload = await rpc.start({
    title,
    description,
    visibility,
    sourceLocale,
    sourceMimeType: file.type || "application/octet-stream",
    sourceSize: file.size,
    ladderPolicy,
  });

  const protocol: MultipartProtocol = {
    presignParts: (input) =>
      rpc.presignParts({
        videoId: upload.videoId,
        uploadId: upload.uploadId,
        partNumbers: input.partNumbers,
      }),
    complete: (input) =>
      rpc.complete({
        videoId: upload.videoId,
        uploadId: upload.uploadId,
        parts: input.parts,
      }),
    abort: () => rpc.abort({ videoId: upload.videoId, uploadId: upload.uploadId }),
    heartbeat: () => rpc.heartbeat({ videoId: upload.videoId }),
  };

  await uploadMultipart({ file, protocol, onProgress, signal });
  return { videoId: upload.videoId };
}

export async function uploadAudioTrack(
  opts: UploadAudioTrackOptions,
): Promise<UploadAudioTrackResult> {
  const { videoId, locale, label, file, onProgress, signal, rpc } = opts;

  const totalParts = Math.max(1, Math.ceil(file.size / PART_SIZE));
  if (totalParts > 10_000) {
    throw new Error("File exceeds the S3 multipart 10,000-part limit. Pick a larger PART_SIZE.");
  }

  const start = await rpc.startAudioTrack({
    videoId,
    locale,
    label,
    mimeType: file.type || "application/octet-stream",
    size: file.size,
  });

  const protocol: MultipartProtocol = {
    presignParts: (input) =>
      rpc.presignAudioTrackParts({
        audioTrackId: start.audioTrackId,
        uploadId: start.uploadId,
        partNumbers: input.partNumbers,
      }),
    complete: (input) =>
      rpc.finalizeAudioTrack({
        audioTrackId: start.audioTrackId,
        uploadId: start.uploadId,
        parts: input.parts,
      }),
    abort: () =>
      rpc.abortAudioTrack({ audioTrackId: start.audioTrackId, uploadId: start.uploadId }),
    heartbeat: () => rpc.heartbeatAudioTrack({ audioTrackId: start.audioTrackId }),
  };

  await uploadMultipart({ file, protocol, onProgress, signal });
  return { audioTrackId: start.audioTrackId };
}

/**
 * Drives the multipart presign → PUT → complete loop for a single file.
 * Bounded concurrency, batched presign, periodic heartbeat, abort-on-error.
 * Error messages are intentionally raw English — they only fire on network
 * or storage failures, which AGENTS.md exempts from i18n.
 */
export async function uploadMultipart(opts: UploadMultipartOptions): Promise<void> {
  const { file, protocol, onProgress, signal, concurrency = PART_CONCURRENCY } = opts;

  const totalParts = Math.max(1, Math.ceil(file.size / PART_SIZE));
  if (totalParts > 10_000) {
    throw new Error("File exceeds the S3 multipart 10,000-part limit. Pick a larger PART_SIZE.");
  }

  const stopHeartbeat = startHeartbeat(protocol);
  let bytesUploaded = 0;
  const completedParts: Array<{ partNumber: number; etag: string }> = [];

  try {
    // Stream presigns in batches; for each presigned URL, PUT the
    // corresponding slice of `file`. A 10GB upload doesn't fit in memory all
    // at once — Blob.slice() returns a view, not a copy.
    let partNumber = 1;
    while (partNumber <= totalParts) {
      if (signal?.aborted) throw new DOMException("Aborted", "AbortError");
      const batchEnd = Math.min(partNumber + PRESIGN_BATCH - 1, totalParts);
      const batchNumbers: number[] = [];
      for (let n = partNumber; n <= batchEnd; n++) batchNumbers.push(n);

      const { parts: presigns } = await protocol.presignParts({ partNumbers: batchNumbers });
      const presignByNumber = new Map(presigns.map((p) => [p.partNumber, p]));

      // Upload this batch with bounded concurrency.
      await runConcurrent(batchNumbers, concurrency, async (n) => {
        const presign = presignByNumber.get(n);
        if (!presign) throw new Error(`Missing presign for part ${n}`);
        const startByte = (n - 1) * PART_SIZE;
        const endByte = Math.min(startByte + PART_SIZE, file.size);
        const slice = file.slice(startByte, endByte);
        const result = await fetch(presign.url, {
          method: "PUT",
          body: slice,
          signal,
        });
        if (!result.ok) {
          throw new Error(`Part ${n} failed (${result.status})`);
        }
        // S3 wraps the ETag in literal quotes — most APIs that consume it
        // want the quotes preserved. We pass it through verbatim.
        const etag = result.headers.get("etag");
        if (!etag) throw new Error(`Part ${n} response missing ETag`);
        completedParts.push({ partNumber: n, etag });
        bytesUploaded += slice.size;
        onProgress?.(Math.min(1, bytesUploaded / file.size));
      });

      partNumber = batchEnd + 1;
    }

    const orderedParts = completedParts.slice().sort((a, b) => a.partNumber - b.partNumber);
    await protocol.complete({ parts: orderedParts });
    onProgress?.(1);
  } catch (err) {
    // Best-effort abort so we don't accrue storage charges on a partial
    // upload. The cleanup-videos cron sweeps anything we miss.
    await protocol.abort().catch(() => {});
    throw err;
  } finally {
    stopHeartbeat();
  }
}

function startHeartbeat(protocol: MultipartProtocol): () => void {
  const timer = setInterval(() => {
    void protocol.heartbeat().catch(() => {});
  }, HEARTBEAT_INTERVAL_MS);
  return () => clearInterval(timer);
}

async function runConcurrent<T>(
  items: T[],
  concurrency: number,
  fn: (item: T) => Promise<void>,
): Promise<void> {
  const queue = items.slice();
  const running: Promise<void>[] = [];
  const errors: unknown[] = [];

  async function spawn(): Promise<void> {
    const item = queue.shift();
    if (item === undefined) return;
    try {
      await fn(item);
    } catch (err) {
      errors.push(err);
    }
    return spawn();
  }

  for (let i = 0; i < Math.min(concurrency, items.length); i++) {
    running.push(spawn());
  }
  await Promise.all(running);
  if (errors.length > 0) {
    throw errors[0];
  }
}
