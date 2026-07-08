/**
 * Typed wrapper around the presigned upload flow. Pure client code — does not
 * import sharp, AWS SDK, or any server-only module, so it bundles cleanly
 * into the web SPA.
 *
 * The browser computes a width/height/blurhash hint, asks the server for a
 * short-lived signed PUT URL, uploads bytes directly to S3, then calls back
 * to confirm the upload landed. Bytes never stream through the app server.
 *
 * Use directly inside a TanStack Query mutationFn:
 *
 *   const upload = useMutation({
 *     mutationFn: (file: File) =>
 *       uploadAsset({ file, visibility: "PUBLIC" }),
 *     onSuccess: (asset) => { ... },
 *   });
 */

import { computeImageHint } from "./asset-image-hint";

export type UploadedAsset = {
  id: string;
  mimeType: string;
  size: number;
  visibility: "PUBLIC" | "RESTRICTED";
  ownerId: string | null;
  width: number | null;
  height: number | null;
  blurhash: string | null;
  status: "PENDING" | "READY";
  metadataState: "CLIENT_HINT" | "SERVER_VERIFIED";
  url: string;
  imageUrl: string | null;
};

export type UploadAssetOptions = {
  file: File;
  visibility?: "PUBLIC" | "RESTRICTED";
  signal?: AbortSignal;
  /** Defaults to "/api/assets" — override only for cross-origin tests. */
  apiBase?: string;
};

type PresignResponse = {
  assetId: string;
  uploadUrl: string;
  headers: Record<string, string>;
  expiresIn: number;
};

/**
 * How often the client tells the server "I'm still uploading." The server's
 * cleanup job reaps PENDING rows whose heartbeat is older than 5 minutes, so
 * a 60-second beat tolerates ~5 missed beats before the row becomes eligible.
 */
const HEARTBEAT_INTERVAL_MS = 60_000;

export async function uploadAsset({
  file,
  visibility = "RESTRICTED",
  signal,
  apiBase = "/api/assets",
}: UploadAssetOptions): Promise<UploadedAsset> {
  // Hint computation runs in parallel with the network request would be a
  // micro-optimization at the cost of clarity — keep it sequential.
  const hint = await computeImageHint(file).catch(() => null);

  const presign = await postJson<PresignResponse>(
    `${apiBase}/presign`,
    {
      mimeType: file.type || "application/octet-stream",
      size: file.size,
      visibility,
      hint,
    },
    signal,
  );

  // Heartbeat runs from the moment the PENDING row exists until finalize
  // either succeeds or definitively fails. The row is seeded with a heartbeat
  // at creation, so the very first beat after HEARTBEAT_INTERVAL_MS is the
  // earliest the client needs to chime in.
  const stopHeartbeat = startHeartbeat(apiBase, presign.assetId);
  try {
    const put = await fetch(presign.uploadUrl, {
      method: "PUT",
      headers: presign.headers,
      body: file,
      signal,
    });
    if (!put.ok) {
      throw new Error(`Direct-to-S3 upload failed (${put.status})`);
    }

    return await postJson<UploadedAsset>(
      `${apiBase}/finalize`,
      { assetId: presign.assetId },
      signal,
    );
  } finally {
    stopHeartbeat();
  }
}

function startHeartbeat(apiBase: string, assetId: string): () => void {
  const timer = setInterval(() => {
    // Fire-and-forget; a failed heartbeat is best-effort, and the cleanup
    // window is long enough that one or two misses are harmless.
    void fetch(`${apiBase}/heartbeat`, {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ assetId }),
      // Use keepalive so the beat still flushes if the tab is closing.
      keepalive: true,
    }).catch(() => {});
  }, HEARTBEAT_INTERVAL_MS);
  return () => clearInterval(timer);
}

async function postJson<T>(url: string, body: unknown, signal?: AbortSignal): Promise<T> {
  const response = await fetch(url, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    signal,
  });
  if (!response.ok) {
    throw new Error(await safeErrorMessage(response));
  }
  return (await response.json()) as T;
}

async function safeErrorMessage(response: Response): Promise<string> {
  try {
    const data = (await response.json()) as { error?: string };
    return data.error ?? `Request failed (${response.status})`;
  } catch {
    return `Request failed (${response.status})`;
  }
}
