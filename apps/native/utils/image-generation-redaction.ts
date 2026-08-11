/**
 * Image-generation redaction for the native remote UI.
 *
 * Mirrors the forbidden-sentinel scan in
 * `crates/cockpit-core/src/image_generation_control_plane`. Secret values,
 * signed query strings, raw workflow/provider payloads, quarantine handles,
 * and unauthorized host paths never enter state, logs, or UI.
 */

// ---------------------------------------------------------------------------
// Forbidden sentinels
// ---------------------------------------------------------------------------

/** Forbidden sentinel strings that must never appear in safe projections, responses, events, or errors. */
export const FORBIDDEN_SENTINELS: readonly string[] = [
  "api_key",
  "apiKey",
  "secret",
  "password",
  "credential",
  "private_key",
  "privateKey",
  "access_token",
  "accessToken",
  "refresh_token",
  "refreshToken",
  "provider_body",
  "providerBody",
  "quarantine",
  "local_path",
  "localPath",
  "host_path",
  "hostPath",
  "raw_workflow_json",
  "rawWorkflowJson",
  "signed_url",
  "signedUrl",
  "connected_ip",
  "connectedIp",
];

/** Scan a JSON-compatible value for forbidden sentinel strings in its keys. */
export function scanForForbiddenSentinels(value: unknown): string[] {
  const found = new Set<string>();
  scanValueKeys(value, found);
  return [...found].sort();
}

function scanValueKeys(value: unknown, found: Set<string>) {
  if (value === null || typeof value !== "object") return;
  if (Array.isArray(value)) {
    for (const item of value) scanValueKeys(item, found);
    return;
  }
  const record = value as Record<string, unknown>;
  for (const key of Object.keys(record)) {
    const keyLower = key.toLowerCase();
    for (const sentinel of FORBIDDEN_SENTINELS) {
      if (keyLower.includes(sentinel.toLowerCase())) {
        found.add(key);
      }
    }
    scanValueKeys(record[key], found);
  }
}

/** Returns `true` if a value contains any forbidden sentinel key. */
export function containsForbiddenSentinel(value: unknown): boolean {
  return scanForForbiddenSentinels(value).length > 0;
}

/** A device/daemon path string that must never be opened as a device path. */
export function isHostPathString(value: unknown): boolean {
  if (typeof value !== "string") return false;
  return value.startsWith("file://") || value.startsWith("/") || /^[a-zA-Z]:[\\/]/.test(value);
}

/** A provider URL string that must never be rendered or opened. */
export function isProviderUrlString(value: unknown): boolean {
  if (typeof value !== "string") return false;
  return /^https?:\/\//i.test(value) && !value.startsWith("https://flycockpit.");
}

/** A signed query string that must never enter state/log/UI. */
export function isSignedQueryString(value: unknown): boolean {
  if (typeof value !== "string") return false;
  return (
    value.includes("sig=") || value.includes("signature=") || value.includes("X-Goog-Signature")
  );
}

/** A raw workflow JSON string that must never be rendered. */
export function isRawWorkflowJson(value: unknown): boolean {
  if (typeof value !== "string") return false;
  return value.includes("class_type") || value.includes("workflow_nodes");
}

/** Returns `true` if a string value must be redacted from state/log/UI. */
export function isRedactableValue(value: unknown): boolean {
  return (
    isHostPathString(value) ||
    isProviderUrlString(value) ||
    isSignedQueryString(value) ||
    isRawWorkflowJson(value)
  );
}

/** Redact a string value, preserving length for layout but masking content. */
export function redactString(value: string): string {
  if (value.length === 0) return value;
  return "•".repeat(Math.min(value.length, 8));
}

/** Deep-clone a JSON-compatible value and redact any forbidden sentinel values. */
export function redactForbiddenValues<T>(value: T): T {
  return redactValueRecursive(value, new WeakSet<object>()) as T;
}

function redactValueRecursive(value: unknown, seen: WeakSet<object>): unknown {
  if (value === null || typeof value !== "object") {
    if (typeof value === "string" && isRedactableValue(value)) {
      return redactString(value);
    }
    return value;
  }
  if (Array.isArray(value)) {
    if (seen.has(value)) return value;
    seen.add(value);
    return value.map((item) => redactValueRecursive(item, seen));
  }
  if (seen.has(value)) return value;
  seen.add(value);
  const record = value as Record<string, unknown>;
  const next: Record<string, unknown> = {};
  for (const key of Object.keys(record)) {
    next[key] = redactValueRecursive(record[key], seen);
  }
  return next;
}

/** Assert that a value is safe to enter state/log/UI. Throws on a forbidden sentinel. */
export function assertSafeForState(value: unknown, context: string): void {
  const found = scanForForbiddenSentinels(value);
  if (found.length > 0) {
    throw new Error(
      `image-generation redaction violation in ${context}: forbidden keys ${found.join(", ")}`,
    );
  }
}
