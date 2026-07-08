const blockedUploadMimeTypes = new Set([
  "application/ecmascript",
  "application/javascript",
  "application/xhtml+xml",
  "image/svg+xml",
  "text/html",
  "text/javascript",
]);

export function isAllowedUploadMimeType(value: string): boolean {
  const mimeType = normalizeMimeType(value);
  if (!/^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/.test(mimeType)) return false;
  return !blockedUploadMimeTypes.has(mimeType);
}

export function normalizeMimeType(value: string): string {
  return value.split(";", 1)[0]?.trim().toLowerCase() ?? "";
}
