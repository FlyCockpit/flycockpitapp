import { lookup } from "node:dns/promises";
import type { IncomingMessage } from "node:http";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { isIP } from "node:net";
import {
  AssetError,
  type AssetMeta,
  type AssetVisibility,
  assetCacheControl,
  fetchAsset,
  finalizeAsset,
  heartbeatAsset,
  presignAsset,
  type Viewer,
} from "@flycockpit/api/lib/assets";
import {
  parseTransformParams,
  type TransformParams,
  transformImage,
} from "@flycockpit/api/lib/images";
import { storage } from "@flycockpit/api/lib/storage";
import type { Session } from "@flycockpit/auth";
import { env } from "@flycockpit/env/server";
import { analyzeAssetQueue } from "@flycockpit/queue";
import type { Env, Hono } from "hono";
import { isPrivateIp } from "./private-ip.js";
import { isAllowedUploadMimeType, normalizeMimeType } from "./upload-mime.js";

/**
 * Mounts:
 *   POST /api/assets/presign      — issue a short-lived signed PUT URL +
 *                                   create a PENDING Asset row
 *   POST /api/assets/finalize     — confirm the upload landed in S3, flip
 *                                   the row to READY, enqueue analyze-asset
 *   GET  /api/assets/:id          — raw asset (visibility-aware caching)
 *   GET  /api/images/:source      — sharp transforms; :source is either an
 *                                   asset id or (when configured) an external
 *                                   URL on the IMAGE_PROXY_ALLOWED_HOSTS list
 *
 * Bytes never stream through this server on the upload path — the browser
 * PUTs directly to S3 with the signed URL. The app sees only metadata.
 *
 * Permissions live in @flycockpit/api/lib/assets — fetchAsset() is the single
 * permission boundary used by both read routes. The image endpoint inherits
 * cache headers from the source's visibility so a transformation of a
 * private asset never leaks into a shared CDN cache.
 */

const allowedExternalHosts: ReadonlySet<string> = new Set(
  env.IMAGE_PROXY_ALLOWED_HOSTS.split(",")
    .map((h) => h.trim().toLowerCase())
    .filter(Boolean),
);

const inlineAssetMimeTypes = new Set([
  "image/avif",
  "image/gif",
  "image/jpeg",
  "image/png",
  "image/webp",
]);

type SessionEnv = { Variables: { session: Session | null } };

export function mountAssetRoutes<E extends Env & SessionEnv>(app: Hono<E>): Hono<E> {
  app.post("/api/assets/presign", async (c) => {
    if (!storage)
      return jsonResponse(
        { error: "File storage is temporarily unavailable. Try again shortly." },
        503,
      );

    const session = c.get("session");
    if (!session?.user) return jsonResponse({ error: "Unauthorized" }, 401);

    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      return jsonResponse({ error: "Request must be valid JSON." }, 400);
    }

    const parsed = parsePresignBody(body);
    if (!parsed.ok) return jsonResponse({ error: parsed.error }, 400);

    if (parsed.value.size > env.ASSET_UPLOAD_MAX_BYTES) {
      const limitMb = Math.round(env.ASSET_UPLOAD_MAX_BYTES / (1024 * 1024));
      return jsonResponse(
        {
          error:
            limitMb > 0 ? `File is too large. Max size is ${limitMb} MB.` : "File is too large.",
        },
        413,
      );
    }

    try {
      const result = await presignAsset({
        mimeType: parsed.value.mimeType,
        size: parsed.value.size,
        visibility: parsed.value.visibility,
        ownerId: session.user.id,
        hint: parsed.value.hint,
      });
      return jsonResponse(
        {
          assetId: result.assetId,
          uploadUrl: result.upload.url,
          headers: result.upload.headers,
          expiresIn: result.upload.expiresIn,
        },
        201,
      );
    } catch (err) {
      console.error("[asset-routes] Presign failed:", err);
      return jsonResponse({ error: "Presign failed" }, 500);
    }
  });

  app.post("/api/assets/finalize", async (c) => {
    if (!storage)
      return jsonResponse(
        { error: "File storage is temporarily unavailable. Try again shortly." },
        503,
      );

    const session = c.get("session");
    if (!session?.user) return jsonResponse({ error: "Unauthorized" }, 401);

    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      return jsonResponse({ error: "Request must be valid JSON." }, 400);
    }

    const assetId = parseAssetId(body);
    if (!assetId) return jsonResponse({ error: "Asset ID is missing." }, 400);

    const viewer = viewerFromSession(session);
    try {
      const meta = await finalizeAsset({ assetId, viewer });
      // Best-effort: if the queue is unreachable we still return the row.
      // Without a worker pass, the metadata stays at the client-supplied
      // hint — which is acceptable for visual data (see the asset pipeline notes
      // § Alternative: presigned uploads).
      analyzeAssetQueue
        .add("analyze-asset", { assetId: meta.id })
        .catch((err) => console.warn("[asset-routes] enqueue analyze-asset failed:", err));
      return jsonResponse(serializeAsset(meta), 200);
    } catch (err) {
      return assetErrorResponse(err);
    }
  });

  app.post("/api/assets/heartbeat", async (c) => {
    if (!storage) return jsonResponse({ error: "Asset storage is not configured" }, 503);

    const session = c.get("session");
    if (!session?.user) return jsonResponse({ error: "Unauthorized" }, 401);

    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      return jsonResponse({ error: "Invalid JSON body" }, 400);
    }

    const assetId = parseAssetId(body);
    if (!assetId) return jsonResponse({ error: "assetId is required" }, 400);

    const viewer = viewerFromSession(session);
    try {
      await heartbeatAsset({ assetId, viewer });
      return jsonResponse({ ok: true }, 200);
    } catch (err) {
      return assetErrorResponse(err);
    }
  });

  app.get("/api/assets/:id", async (c) => {
    if (!storage)
      return jsonResponse(
        { error: "File storage is temporarily unavailable. Try again shortly." },
        503,
      );

    const viewer = viewerFromSession(c.get("session"));
    try {
      const { meta, body } = await fetchAsset(c.req.param("id"), viewer);
      return assetResponse(meta, body.body, body.contentType);
    } catch (err) {
      return assetErrorResponse(err);
    }
  });

  app.get("/api/images/:source", async (c) => {
    const params = parseTransformParams(new URL(c.req.url).searchParams);
    const source = decodeURIComponent(c.req.param("source"));

    if (isExternalUrl(source)) {
      return handleExternalImage(source, params);
    }

    if (!storage)
      return jsonResponse(
        { error: "File storage is temporarily unavailable. Try again shortly." },
        503,
      );

    const viewer = viewerFromSession(c.get("session"));
    try {
      const { meta, body } = await fetchAsset(source, viewer);
      if (!meta.mimeType.startsWith("image/")) {
        return jsonResponse({ error: "That file isn't a valid image." }, 400);
      }
      const transformed = await transformImage(body.body, params);
      return imageResponse(transformed.body, transformed.contentType, meta.visibility);
    } catch (err) {
      return assetErrorResponse(err);
    }
  });

  return app;
}

async function handleExternalImage(source: string, params: TransformParams): Promise<Response> {
  const validation = validateExternalImageUrl(source);
  if (!validation.ok) return validation.response;
  const url = validation.url;

  // Resolve and SSRF-check the hostname exactly once, then pin those addresses
  // onto the outbound request (see fetchPinned). Doing the lookup here and
  // reusing its result at connect time closes the DNS-rebinding TOCTOU: there
  // is no second, independent resolution that an attacker-controlled record
  // could flip from a public to a private/link-local IP between check and fetch.
  const resolved = await resolvePublicAddresses(url.hostname);
  if (!resolved.ok) {
    return jsonResponse({ error: "That image host isn't allowed." }, 403);
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), env.IMAGE_PROXY_TIMEOUT_MS);
  let upstream: IncomingMessage;
  try {
    upstream = await fetchPinned(url, resolved.addresses, controller.signal);
  } catch (err) {
    clearTimeout(timeout);
    if (err instanceof DOMException && err.name === "AbortError") {
      return jsonResponse(
        { error: "We couldn't fetch that image. Try again, or use a different image." },
        504,
      );
    }
    return jsonResponse(
      { error: "We couldn't fetch that image. Try again, or use a different image." },
      502,
    );
  }

  try {
    const status = upstream.statusCode ?? 0;
    if (status >= 300 && status < 400) {
      upstream.destroy();
      return jsonResponse({ error: "Image proxy redirects are not allowed." }, 400);
    }
    if (status < 200 || status >= 300) {
      upstream.destroy();
      return jsonResponse(
        { error: "We couldn't fetch that image. Try again, or use a different image." },
        502,
      );
    }
    const contentType = headerValue(upstream.headers["content-type"]) ?? "";
    if (!contentType.startsWith("image/")) {
      upstream.destroy();
      return jsonResponse(
        { error: "That URL doesn't point to an image. Check the link and try again." },
        400,
      );
    }

    const declaredLength = headerValue(upstream.headers["content-length"]);
    if (declaredLength && Number(declaredLength) > env.IMAGE_PROXY_MAX_BYTES) {
      upstream.destroy();
      return jsonResponse({ error: "That image is too large to proxy." }, 413);
    }

    const upstreamBytes = await readBodyWithLimit(upstream, env.IMAGE_PROXY_MAX_BYTES);
    const transformed = await transformImage(upstreamBytes, params);
    // External hosts on the allowlist are treated as PUBLIC for caching —
    // the operator opted them in, and they're already publicly reachable.
    return imageResponse(transformed.body, transformed.contentType, "PUBLIC");
  } catch (err) {
    if (err instanceof BodyTooLargeError) {
      return jsonResponse({ error: "That image is too large to proxy." }, 413);
    }
    if (err instanceof DOMException && err.name === "AbortError") {
      return jsonResponse(
        { error: "We couldn't fetch that image. Try again, or use a different image." },
        504,
      );
    }
    console.error("[asset-routes] External image proxy failed:", err);
    return jsonResponse({ error: "Something didn't work on our end. Try again in a moment." }, 500);
  } finally {
    clearTimeout(timeout);
  }
}

function validateExternalImageUrl(
  source: string,
): { ok: true; url: URL } | { ok: false; response: Response } {
  let url: URL;
  try {
    url = new URL(source);
  } catch {
    return {
      ok: false,
      response: jsonResponse(
        { error: "That URL doesn't look right. Double-check it and try again." },
        400,
      ),
    };
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    return {
      ok: false,
      response: jsonResponse({ error: "Only http or https URLs are allowed." }, 400),
    };
  }
  if (!allowedExternalHosts.has(url.hostname.toLowerCase())) {
    return {
      ok: false,
      response: jsonResponse(
        { error: "That image host isn't allowed. Ask an admin to add it to the allowed list." },
        403,
      ),
    };
  }
  return { ok: true, url };
}

type ResolvedAddress = { address: string; family: number };

/**
 * Resolve `hostname` to its A/AAAA records and confirm EVERY one is publicly
 * routable. Returns the records on success so the caller can pin them onto the
 * outbound connection. Fails closed: an unresolvable host, an empty answer, or
 * any single private/link-local/loopback/CGNAT address blocks the whole host
 * (a round-robin record can't smuggle one internal target past the guard).
 */
async function resolvePublicAddresses(
  hostname: string,
): Promise<{ ok: true; addresses: ResolvedAddress[] } | { ok: false }> {
  if (isPrivateHostname(hostname)) return { ok: false };

  const literalVersion = isIP(hostname);
  if (literalVersion !== 0) {
    if (isPrivateIp(hostname, literalVersion)) return { ok: false };
    return { ok: true, addresses: [{ address: hostname, family: literalVersion }] };
  }

  let records: ResolvedAddress[];
  try {
    records = await lookup(hostname, { all: true, verbatim: true });
  } catch {
    return { ok: false };
  }

  if (records.length === 0) return { ok: false };
  if (records.some((record) => isPrivateIp(record.address, record.family))) {
    return { ok: false };
  }
  return { ok: true, addresses: records };
}

/**
 * Issue the proxied GET, pinning DNS to the already-validated addresses via a
 * `lookup` hook so the socket connects to exactly what `resolvePublicAddresses`
 * vetted — never a freshly-resolved (and possibly rebind-flipped) IP. Redirects
 * are not followed; the caller rejects any 3xx.
 */
function fetchPinned(
  url: URL,
  addresses: ResolvedAddress[],
  signal: AbortSignal,
): Promise<IncomingMessage> {
  const pinnedLookup = ((
    _hostname: string,
    options: unknown,
    callback: (...cbArgs: unknown[]) => void,
  ) => {
    const wantsAll =
      typeof options === "object" && options !== null && (options as { all?: boolean }).all;
    const first = addresses[0];
    if (wantsAll || !first) {
      callback(null, addresses);
    } else {
      callback(null, first.address, first.family);
    }
  }) as unknown as Parameters<typeof httpsRequest>[1]["lookup"];

  const options = { method: "GET", signal, lookup: pinnedLookup };
  return new Promise<IncomingMessage>((resolve, reject) => {
    const req =
      url.protocol === "https:"
        ? httpsRequest(url, options, resolve)
        : httpRequest(url, options, resolve);
    req.on("error", reject);
    req.end();
  });
}

function headerValue(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

function isPrivateHostname(hostname: string): boolean {
  const normalized = hostname.toLowerCase().replace(/\.$/, "");
  return normalized === "localhost" || normalized.endsWith(".localhost");
}

class BodyTooLargeError extends Error {}

async function readBodyWithLimit(stream: AsyncIterable<Uint8Array>, maxBytes: number) {
  const chunks: Uint8Array[] = [];
  let total = 0;
  for await (const chunk of stream) {
    total += chunk.byteLength;
    if (total > maxBytes) {
      throw new BodyTooLargeError();
    }
    chunks.push(chunk);
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return out;
}

function isExternalUrl(value: string): boolean {
  return value.startsWith("http://") || value.startsWith("https://");
}

function viewerFromSession(session: Session | null | undefined): Viewer {
  if (!session?.user) return { kind: "anonymous" };
  return { kind: "user", userId: session.user.id, role: session.user.role ?? "user" };
}

function assetResponse(meta: AssetMeta, body: Uint8Array, contentType: string): Response {
  const normalizedContentType = normalizeMimeType(contentType);
  const disposition = inlineAssetMimeTypes.has(normalizedContentType) ? "inline" : "attachment";

  return new Response(body, {
    status: 200,
    headers: {
      "Content-Type": contentType,
      "Content-Length": String(body.byteLength),
      "Content-Disposition": disposition,
      "Content-Security-Policy": "sandbox",
      "Cache-Control": assetCacheControl(meta.visibility),
      ETag: `"${meta.id}"`,
    },
  });
}

function imageResponse(
  body: Buffer,
  contentType: string,
  visibility: AssetMeta["visibility"],
): Response {
  return new Response(new Uint8Array(body), {
    status: 200,
    headers: {
      "Content-Type": contentType,
      "Content-Length": String(body.byteLength),
      "Cache-Control": assetCacheControl(visibility),
    },
  });
}

function parseVisibility(value: unknown): AssetVisibility | null {
  if (value === "PUBLIC" || value === "RESTRICTED") return value;
  if (value === undefined || value === null || value === "") return "RESTRICTED";
  return null;
}

type ParsedPresignBody = {
  mimeType: string;
  size: number;
  visibility: AssetVisibility;
  hint?: { width?: number | null; height?: number | null; blurhash?: string | null };
};

function parsePresignBody(
  raw: unknown,
): { ok: true; value: ParsedPresignBody } | { ok: false; error: string } {
  if (!raw || typeof raw !== "object")
    return { ok: false, error: "Request body is invalid or empty." };
  const body = raw as Record<string, unknown>;

  const mimeType = typeof body.mimeType === "string" ? body.mimeType : "";
  if (!mimeType) return { ok: false, error: "File type is missing." };
  if (!isAllowedUploadMimeType(mimeType)) {
    return { ok: false, error: "That file type isn't allowed." };
  }

  const sizeRaw = body.size;
  if (typeof sizeRaw !== "number" || !Number.isFinite(sizeRaw) || sizeRaw <= 0) {
    return { ok: false, error: "File size must be a positive number." };
  }
  const size = Math.floor(sizeRaw);

  const visibility = parseVisibility(body.visibility);
  if (!visibility) {
    return { ok: false, error: "Visibility must be PUBLIC or RESTRICTED." };
  }

  let hint: ParsedPresignBody["hint"];
  if (body.hint && typeof body.hint === "object") {
    const h = body.hint as Record<string, unknown>;
    hint = {
      width: typeof h.width === "number" && h.width > 0 ? Math.floor(h.width) : null,
      height: typeof h.height === "number" && h.height > 0 ? Math.floor(h.height) : null,
      blurhash: typeof h.blurhash === "string" && h.blurhash.length > 0 ? h.blurhash : null,
    };
  }

  return { ok: true, value: { mimeType, size, visibility, hint } };
}

function parseAssetId(raw: unknown): string | null {
  if (!raw || typeof raw !== "object") return null;
  const id = (raw as { assetId?: unknown }).assetId;
  return typeof id === "string" && id.length > 0 ? id : null;
}

function serializeAsset(asset: AssetMeta) {
  return {
    id: asset.id,
    mimeType: asset.mimeType,
    size: asset.size,
    visibility: asset.visibility,
    ownerId: asset.ownerId,
    width: asset.width,
    height: asset.height,
    blurhash: asset.blurhash,
    status: asset.status,
    metadataState: asset.metadataState,
    url: `/api/assets/${asset.id}`,
    imageUrl: asset.mimeType.startsWith("image/") ? `/api/images/${asset.id}` : null,
  };
}

function jsonResponse(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function assetErrorResponse(err: unknown): Response {
  if (err instanceof AssetError) {
    if (err.code === "STORAGE_DISABLED") {
      return jsonResponse(
        { error: "File storage is temporarily unavailable. Try again shortly." },
        503,
      );
    }
    if (err.code === "GONE") {
      return jsonResponse({ error: "That file was deleted or is no longer available." }, 410);
    }
    if (err.code === "UPLOAD_MISSING") {
      return jsonResponse({ error: "File storage state is inconsistent. Contact an admin." }, 409);
    }
    if (err.code === "SIZE_MISMATCH") {
      return jsonResponse(
        { error: "File size mismatch. The upload may be incomplete. Try again." },
        409,
      );
    }
    // 404 for both NOT_FOUND and FORBIDDEN — don't leak existence to
    // unauthenticated probes.
    return jsonResponse({ error: "Not found" }, 404);
  }
  console.error("[asset-routes] Unexpected error:", err);
  return jsonResponse({ error: "Something didn't work on our end. Try again in a moment." }, 500);
}
