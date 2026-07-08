import { env } from "@flycockpit/env/server";
import { encode as encodeBlurhash } from "blurhash";
import sharp from "sharp";

/**
 * Image utilities used by the upload procedure (extract metadata + compute
 * blurhash on save) and the image transform endpoint (resize/recompress on
 * read).
 *
 * Sharp is the only image library we ship — same library across upload and
 * transform paths so behavior is consistent.
 */

const BLURHASH_PREVIEW_MAX = 32;
const BLURHASH_COMPONENTS_X = 4;
const BLURHASH_COMPONENTS_Y = 3;

const TRANSFORM_MAX_DIMENSION = 4096;
const TRANSFORM_DEFAULT_QUALITY = 80;

export type ImageMetadata = {
  width: number;
  height: number;
  mimeType: string;
};

export type UploadImageAnalysis = ImageMetadata & {
  blurhash: string;
};

/**
 * Extract dimensions + a blurhash placeholder from an image buffer. Used at
 * upload time so the placeholder is computed once and stored on the Asset
 * row, not recomputed on every read.
 */
export async function analyzeImage(
  buffer: Uint8Array | Buffer,
  declaredMimeType: string,
): Promise<UploadImageAnalysis | null> {
  const input = Buffer.isBuffer(buffer) ? buffer : Buffer.from(buffer);
  const sharpOptions = { limitInputPixels: env.IMAGE_TRANSFORM_MAX_INPUT_PIXELS };
  let metadata: sharp.Metadata;
  try {
    metadata = await sharp(input, sharpOptions).metadata();
  } catch {
    return null;
  }
  if (!metadata.width || !metadata.height || !metadata.format) return null;

  const { data, info } = await sharp(input, sharpOptions)
    .resize(BLURHASH_PREVIEW_MAX, BLURHASH_PREVIEW_MAX, {
      fit: "inside",
      withoutEnlargement: false,
    })
    .ensureAlpha()
    .raw()
    .toBuffer({ resolveWithObject: true });

  const pixels = new Uint8ClampedArray(data.buffer, data.byteOffset, data.byteLength);
  const blurhash = encodeBlurhash(
    pixels,
    info.width,
    info.height,
    BLURHASH_COMPONENTS_X,
    BLURHASH_COMPONENTS_Y,
  );

  return {
    width: metadata.width,
    height: metadata.height,
    mimeType: declaredMimeType,
    blurhash,
  };
}

export type TransformParams = {
  width?: number;
  height?: number;
  quality?: number;
  format?: "webp" | "avif" | "jpeg" | "png";
};

export type TransformResult = {
  body: Buffer;
  contentType: string;
};

/**
 * Resize and recompress an image. Defaults to webp at quality 80, which
 * is a good baseline for web delivery (small + universally supported in
 * 2025+). Hard-caps dimensions at 4096 to prevent DoS via huge requested
 * sizes.
 */
export async function transformImage(
  source: Uint8Array | Buffer,
  params: TransformParams,
): Promise<TransformResult> {
  const input = Buffer.isBuffer(source) ? source : Buffer.from(source);
  const width = clampDimension(params.width);
  const height = clampDimension(params.height);
  const quality = clampQuality(params.quality);
  const format = params.format ?? "webp";

  let pipeline = sharp(input, { limitInputPixels: env.IMAGE_TRANSFORM_MAX_INPUT_PIXELS });

  if (width || height) {
    pipeline = pipeline.resize({
      width: width ?? undefined,
      height: height ?? undefined,
      fit: "inside",
      withoutEnlargement: true,
    });
  }

  switch (format) {
    case "webp":
      pipeline = pipeline.webp({ quality });
      return { body: await pipeline.toBuffer(), contentType: "image/webp" };
    case "avif":
      pipeline = pipeline.avif({ quality });
      return { body: await pipeline.toBuffer(), contentType: "image/avif" };
    case "jpeg":
      pipeline = pipeline.jpeg({ quality });
      return { body: await pipeline.toBuffer(), contentType: "image/jpeg" };
    case "png":
      pipeline = pipeline.png({ quality });
      return { body: await pipeline.toBuffer(), contentType: "image/png" };
  }
}

export function parseTransformParams(searchParams: URLSearchParams): TransformParams {
  const w = searchParams.get("w");
  const h = searchParams.get("h");
  const q = searchParams.get("q");
  const format = searchParams.get("format");

  return {
    width: w ? Number.parseInt(w, 10) : undefined,
    height: h ? Number.parseInt(h, 10) : undefined,
    quality: q ? Number.parseInt(q, 10) : undefined,
    format: parseFormat(format),
  };
}

function parseFormat(value: string | null): TransformParams["format"] {
  if (value === "webp" || value === "avif" || value === "jpeg" || value === "png") {
    return value;
  }
  return undefined;
}

function clampDimension(value: number | undefined): number | undefined {
  if (!value || !Number.isFinite(value) || value <= 0) return undefined;
  return Math.min(Math.floor(value), TRANSFORM_MAX_DIMENSION);
}

function clampQuality(value: number | undefined): number {
  if (!value || !Number.isFinite(value)) return TRANSFORM_DEFAULT_QUALITY;
  return Math.min(Math.max(Math.floor(value), 1), 100);
}
