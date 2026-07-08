import { encode } from "blurhash";

/**
 * Compute a width/height/blurhash hint from an image File entirely in the
 * browser. Used by the presigned upload flow so the Asset row carries usable
 * placeholder metadata from the moment it's created — even before the
 * analyze-asset worker runs.
 *
 * Returns null for non-image files, for files the browser can't decode, or
 * when the page lacks `OffscreenCanvas` (Safari ≤ 16.3 / older WebViews) and
 * the caller wants to skip rather than fall back. The fallback path uses a
 * regular `<canvas>` element when one is reachable; the function is safe to
 * call from anywhere a `document` exists.
 */
export async function computeImageHint(file: File): Promise<{
  width: number;
  height: number;
  blurhash: string;
} | null> {
  if (!file.type.startsWith("image/")) return null;

  let bitmap: ImageBitmap;
  try {
    bitmap = await createImageBitmap(file);
  } catch {
    return null;
  }

  const sampleW = 32;
  const sampleH = Math.max(1, Math.round((bitmap.height / bitmap.width) * sampleW));

  const ctx = getDownsampleContext(sampleW, sampleH);
  if (!ctx) {
    bitmap.close?.();
    return null;
  }
  ctx.drawImage(bitmap, 0, 0, sampleW, sampleH);
  const { data } = ctx.getImageData(0, 0, sampleW, sampleH);

  const result = {
    width: bitmap.width,
    height: bitmap.height,
    blurhash: encode(data, sampleW, sampleH, 4, 3),
  };
  bitmap.close?.();
  return result;
}

type DownsampleContext = Pick<CanvasRenderingContext2D, "drawImage" | "getImageData">;

function getDownsampleContext(width: number, height: number): DownsampleContext | null {
  if (typeof OffscreenCanvas !== "undefined") {
    const canvas = new OffscreenCanvas(width, height);
    return canvas.getContext("2d") as unknown as DownsampleContext | null;
  }
  if (typeof document === "undefined") return null;
  const canvas = document.createElement("canvas");
  canvas.width = width;
  canvas.height = height;
  return canvas.getContext("2d");
}
