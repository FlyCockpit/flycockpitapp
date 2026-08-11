/**
 * Image-generation native reference upload state machine.
 *
 * Device references come from the platform picker and are copied/read
 * through Expo APIs, validated against typed media limits, then uploaded as
 * session attachments. Each selection/upload has an opaque `upload_id` plus
 * monotonic selection epoch.
 *
 * Cancel invokes transport abort, retires the ID, and cleans the app-sandbox
 * temporary copy when no active consumer remains. Progress/completion for a
 * retired ID, prior epoch, prior session/project, or prior daemon instance
 * is ignored. A successful opaque attachment handle—not a `content://`,
 * `file://`, Photo Library URI, or display name—enters planning.
 */

import { containsForbiddenSentinel, isHostPathString } from "./image-generation-redaction";

// ---------------------------------------------------------------------------
// Media limits
// ---------------------------------------------------------------------------

/** The typed media limits for reference upload validation. */
export interface ReferenceMediaLimits {
  /** Maximum byte length for a single reference. */
  maxByteLength: number;
  /** Allowed MIME kinds. */
  allowedMimeKinds: readonly string[];
  /** Maximum width in pixels (0 = unlimited). */
  maxWidth: number;
  /** Maximum height in pixels (0 = unlimited). */
  maxHeight: number;
  /** Maximum number of references per session. */
  maxReferencesPerSession: number;
}

/** The default typed media limits matching the control plane. */
export const DEFAULT_REFERENCE_MEDIA_LIMITS: ReferenceMediaLimits = {
  maxByteLength: 16 * 1024 * 1024,
  allowedMimeKinds: ["image/png", "image/jpeg", "image/webp", "image/svg+xml"],
  maxWidth: 16_384,
  maxHeight: 16_384,
  maxReferencesPerSession: 16,
};

// ---------------------------------------------------------------------------
// Selection source
// ---------------------------------------------------------------------------

/** The platform picker source for a reference selection. */
export type ReferenceSelectionSource = "content" | "file" | "library";

// ---------------------------------------------------------------------------
// Upload state
// ---------------------------------------------------------------------------

/** The upload lifecycle state for a single reference. */
export type UploadState =
  | "selecting"
  | "copying"
  | "validating"
  | "uploading"
  | "completed"
  | "cancelled"
  | "failed";

/** Terminal upload states. */
export const TERMINAL_UPLOAD_STATES: readonly UploadState[] = ["completed", "cancelled", "failed"];

/** Returns `true` if the upload state is terminal. */
export function isTerminalUploadState(state: UploadState): boolean {
  return TERMINAL_UPLOAD_STATES.includes(state);
}

// ---------------------------------------------------------------------------
// Upload record
// ---------------------------------------------------------------------------

/** A single reference upload record with opaque ID and monotonic epoch. */
export interface ReferenceUploadRecord {
  /** Opaque upload ID; never a `content://`, `file://`, or display name. */
  uploadId: string;
  /** Monotonic selection epoch; prior-epoch events are ignored. */
  selectionEpoch: number;
  /** The platform picker source. */
  source: ReferenceSelectionSource;
  /** The app-sandbox temporary copy URI (never the original `content://`/`file://`). */
  sandboxCopyUri: string | null;
  /** The session this upload belongs to. */
  sessionId: string;
  /** The project this upload belongs to. */
  projectId: string;
  /** The daemon instance this upload belongs to. */
  daemonInstanceId: string;
  /** Current upload state. */
  state: UploadState;
  /** Progress fraction in `[0,1]`. */
  progress: number;
  /** The opaque attachment handle on success; never a device path. */
  attachmentHandle: string | null;
  /** A stable, non-leaking error code on failure. */
  errorCode: string | null;
  /** The number of active consumers of the sandbox copy (for cleanup). */
  activeConsumers: number;
  /** Monotonic clock for ordering. */
  createdAt: number;
}

/** The upload state machine store. */
export interface ReferenceUploadStore {
  /** Uploads keyed by opaque upload ID. */
  uploads: Map<string, ReferenceUploadRecord>;
  /** The monotonic selection epoch counter. */
  selectionEpoch: number;
  /** The current daemon instance ID (for identity gating). */
  daemonInstanceId: string;
  /** The current project ID (for identity gating). */
  projectId: string;
  /** The current session ID (for identity gating). */
  sessionId: string;
}

/** Create an empty upload store bound to a daemon/project/session identity. */
export function createReferenceUploadStore(identity: {
  daemonInstanceId: string;
  projectId: string;
  sessionId: string;
}): ReferenceUploadStore {
  return {
    uploads: new Map(),
    selectionEpoch: 0,
    daemonInstanceId: identity.daemonInstanceId,
    projectId: identity.projectId,
    sessionId: identity.sessionId,
  };
}

// ---------------------------------------------------------------------------
// Upload ID mint
// ---------------------------------------------------------------------------

/** Mint a fresh opaque upload ID. Not a device path, display name, or content URI. */
export function mintUploadId(): string {
  // 22-char unpadded base64url random ID, matching the control plane alias codec.
  const bytes = new Uint8Array(16);
  if (typeof crypto !== "undefined" && crypto.getRandomValues) {
    crypto.getRandomValues(bytes);
  } else {
    // Fallback for environments without crypto.getRandomValues.
    for (let i = 0; i < bytes.length; i++) bytes[i] = Math.floor(Math.random() * 256);
  }
  // Reject zero IDs.
  if (bytes.every((b) => b === 0)) bytes[0] = 1;
  return base64UrlEncode16(bytes);
}

function base64UrlEncode16(bytes: Uint8Array): string {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i] ?? 0;
    const b1 = bytes[i + 1] ?? 0;
    const b2 = bytes[i + 2] ?? 0;
    out += chars[(b0 >> 2) & 0x3f];
    out += chars[((b0 << 4) | (b1 >> 4)) & 0x3f];
    out += chars[((b1 << 2) | (b2 >> 6)) & 0x3f];
    out += chars[b2 & 0x3f];
  }
  // 16 bytes -> 22 chars (last group has 1 byte -> 2 chars, drop 2 padding).
  return out.slice(0, 22);
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/** The result of validating a picked reference against typed media limits. */
export type ReferenceValidationResult =
  | { valid: true; mediaKind: string; byteLength: number; width: number; height: number }
  | { valid: false; errorCode: string };

/** Validate a picked reference against typed media limits. */
export function validateReference(
  input: {
    mediaKind: string;
    byteLength: number;
    width: number;
    height: number;
  },
  limits: ReferenceMediaLimits = DEFAULT_REFERENCE_MEDIA_LIMITS,
): ReferenceValidationResult {
  if (!limits.allowedMimeKinds.includes(input.mediaKind)) {
    return { valid: false, errorCode: "unsupported_media_kind" };
  }
  if (input.byteLength <= 0 || input.byteLength > limits.maxByteLength) {
    return { valid: false, errorCode: "byte_length_out_of_range" };
  }
  if (input.width <= 0 || input.height <= 0) {
    return { valid: false, errorCode: "invalid_dimensions" };
  }
  if (limits.maxWidth > 0 && input.width > limits.maxWidth) {
    return { valid: false, errorCode: "width_exceeds_limit" };
  }
  if (limits.maxHeight > 0 && input.height > limits.maxHeight) {
    return { valid: false, errorCode: "height_exceeds_limit" };
  }
  return {
    valid: true,
    mediaKind: input.mediaKind,
    byteLength: input.byteLength,
    width: input.width,
    height: input.height,
  };
}

/** Reject a picker result URI that is a raw device path (never enters planning). */
export function isRawDeviceUri(uri: string): boolean {
  return uri.startsWith("content://") || uri.startsWith("file://") || isHostPathString(uri);
}

// ---------------------------------------------------------------------------
// Identity gating
// ---------------------------------------------------------------------------

/** Returns `true` if an event/result identity matches the current store identity. */
export function identityMatches(
  store: ReferenceUploadStore,
  identity: { daemonInstanceId: string; projectId: string; sessionId: string },
): boolean {
  return (
    store.daemonInstanceId === identity.daemonInstanceId &&
    store.projectId === identity.projectId &&
    store.sessionId === identity.sessionId
  );
}

/** Returns `true` if an upload record is current (not retired, current epoch or later). */
export function isCurrentUpload(
  store: ReferenceUploadStore,
  uploadId: string,
  selectionEpoch: number,
): boolean {
  const record = store.uploads.get(uploadId);
  if (!record) return false;
  if (record.state === "cancelled" || record.state === "failed") return false;
  if (selectionEpoch < record.selectionEpoch) return false;
  return true;
}

// ---------------------------------------------------------------------------
// Selection / copy / upload transitions
// ---------------------------------------------------------------------------

/** Begin a new selection. Returns the new upload record and bumps the epoch. */
export function beginSelection(
  store: ReferenceUploadStore,
  source: ReferenceSelectionSource,
): ReferenceUploadRecord {
  const selectionEpoch = ++store.selectionEpoch;
  const uploadId = mintUploadId();
  const record: ReferenceUploadRecord = {
    uploadId,
    selectionEpoch,
    source,
    sandboxCopyUri: null,
    sessionId: store.sessionId,
    projectId: store.projectId,
    daemonInstanceId: store.daemonInstanceId,
    state: "selecting",
    progress: 0,
    attachmentHandle: null,
    errorCode: null,
    activeConsumers: 0,
    createdAt: Date.now(),
  };
  store.uploads.set(uploadId, record);
  return record;
}

/** Mark a selection complete and begin copying to the app sandbox. */
export function beginCopy(
  store: ReferenceUploadStore,
  uploadId: string,
  sandboxCopyUri: string,
): ReferenceUploadRecord | null {
  const record = store.uploads.get(uploadId);
  if (!record) return null;
  if (record.state !== "selecting") return null;
  // The sandbox copy URI must not be the raw device URI.
  if (isRawDeviceUri(sandboxCopyUri) && !sandboxCopyUri.startsWith("file://")) {
    return null;
  }
  const next: ReferenceUploadRecord = {
    ...record,
    sandboxCopyUri,
    state: "copying",
    activeConsumers: 1,
  };
  store.uploads.set(uploadId, next);
  return next;
}

/** Mark copy complete and begin validation. */
export function beginValidation(
  store: ReferenceUploadStore,
  uploadId: string,
): ReferenceUploadRecord | null {
  const record = store.uploads.get(uploadId);
  if (!record) return null;
  if (record.state !== "copying") return null;
  const next: ReferenceUploadRecord = { ...record, state: "validating" };
  store.uploads.set(uploadId, next);
  return next;
}

/** Mark validation complete and begin upload. */
export function beginUpload(
  store: ReferenceUploadStore,
  uploadId: string,
): ReferenceUploadRecord | null {
  const record = store.uploads.get(uploadId);
  if (!record) return null;
  if (record.state !== "validating") return null;
  const next: ReferenceUploadRecord = { ...record, state: "uploading" };
  store.uploads.set(uploadId, next);
  return next;
}

/** Report upload progress for a current upload. Ignored for retired/prior-epoch. */
export function reportProgress(
  store: ReferenceUploadStore,
  uploadId: string,
  selectionEpoch: number,
  progress: number,
): ReferenceUploadRecord | null {
  if (!isCurrentUpload(store, uploadId, selectionEpoch)) return null;
  const record = store.uploads.get(uploadId);
  if (!record) return null;
  if (record.state !== "uploading") return null;
  const clamped = Math.max(0, Math.min(1, progress));
  const next: ReferenceUploadRecord = { ...record, progress: clamped };
  store.uploads.set(uploadId, next);
  return next;
}

/** Mark upload complete with an opaque attachment handle. Ignored for retired/prior-epoch. */
export function completeUpload(
  store: ReferenceUploadStore,
  uploadId: string,
  selectionEpoch: number,
  attachmentHandle: string,
  options: { cleanupSandboxCopy?: (uri: string) => void } = {},
): ReferenceUploadRecord | null {
  if (!isCurrentUpload(store, uploadId, selectionEpoch)) return null;
  const record = store.uploads.get(uploadId);
  if (!record) return null;
  if (record.state !== "uploading") return null;
  // The attachment handle must not be a device path or display name.
  if (isRawDeviceUri(attachmentHandle) || containsForbiddenSentinel({ attachmentHandle })) {
    return null;
  }
  const next: ReferenceUploadRecord = {
    ...record,
    state: "completed",
    progress: 1,
    attachmentHandle,
    activeConsumers: Math.max(0, record.activeConsumers - 1),
  };
  store.uploads.set(uploadId, next);
  maybeCleanupSandboxCopy(store, uploadId, next, options.cleanupSandboxCopy);
  return next;
}

/** Mark upload failed with a stable error code. */
export function failUpload(
  store: ReferenceUploadStore,
  uploadId: string,
  errorCode: string,
  options: { cleanupSandboxCopy?: (uri: string) => void } = {},
): ReferenceUploadRecord | null {
  const record = store.uploads.get(uploadId);
  if (!record) return null;
  if (isTerminalUploadState(record.state)) return null;
  const next: ReferenceUploadRecord = {
    ...record,
    state: "failed",
    errorCode,
    activeConsumers: 0,
  };
  store.uploads.set(uploadId, next);
  maybeCleanupSandboxCopy(store, uploadId, next, options.cleanupSandboxCopy);
  return next;
}

// ---------------------------------------------------------------------------
// Cancellation and cleanup
// ---------------------------------------------------------------------------

/** Cancel an in-flight upload: retire the ID, request transport abort, clean sandbox copy. */
export function cancelUpload(
  store: ReferenceUploadStore,
  uploadId: string,
  options: {
    abortTransport?: (uploadId: string) => void;
    cleanupSandboxCopy?: (uri: string) => void;
    requestServerCleanup?: (uploadId: string) => void;
  } = {},
): ReferenceUploadRecord | null {
  const record = store.uploads.get(uploadId);
  if (!record) return null;
  if (isTerminalUploadState(record.state)) return null;
  options.abortTransport?.(uploadId);
  const next: ReferenceUploadRecord = {
    ...record,
    state: "cancelled",
    activeConsumers: 0,
  };
  store.uploads.set(uploadId, next);
  maybeCleanupSandboxCopy(store, uploadId, next, options.cleanupSandboxCopy);
  // Request server attachment cleanup by ID when known (late server success ignored).
  if (record.state === "uploading") {
    options.requestServerCleanup?.(uploadId);
  }
  return next;
}

/** Decrement the active consumer count and clean the sandbox copy when zero remain. */
export function releaseSandboxConsumer(
  store: ReferenceUploadStore,
  uploadId: string,
  cleanupSandboxCopy?: (uri: string) => void,
): ReferenceUploadRecord | null {
  const record = store.uploads.get(uploadId);
  if (!record) return null;
  const next: ReferenceUploadRecord = {
    ...record,
    activeConsumers: Math.max(0, record.activeConsumers - 1),
  };
  store.uploads.set(uploadId, next);
  maybeCleanupSandboxCopy(store, uploadId, next, cleanupSandboxCopy);
  return next;
}

function maybeCleanupSandboxCopy(
  store: ReferenceUploadStore,
  uploadId: string,
  record: ReferenceUploadRecord,
  cleanupSandboxCopy?: (uri: string) => void,
) {
  if (!record.sandboxCopyUri) return;
  if (record.activeConsumers > 0) return;
  if (record.state !== "completed" && record.state !== "cancelled" && record.state !== "failed") {
    return;
  }
  cleanupSandboxCopy?.(record.sandboxCopyUri);
  // The temporary file is namespaced and never read after cleanup.
  const cleared: ReferenceUploadRecord = { ...record, sandboxCopyUri: null };
  store.uploads.set(uploadId, cleared);
}

// ---------------------------------------------------------------------------
// Switch/reconnect: clear pending uploads
// ---------------------------------------------------------------------------

/** Clear all pending uploads, approvals, artifact handles, edits, and cursors on switch/reconnect. */
export function clearPendingUploads(
  store: ReferenceUploadStore,
  options: { cleanupSandboxCopy?: (uri: string) => void } = {},
): ReferenceUploadStore {
  for (const record of store.uploads.values()) {
    if (!isTerminalUploadState(record.state) && record.sandboxCopyUri) {
      options.cleanupSandboxCopy?.(record.sandboxCopyUri);
    }
  }
  return {
    uploads: new Map(),
    selectionEpoch: 0,
    daemonInstanceId: store.daemonInstanceId,
    projectId: store.projectId,
    sessionId: store.sessionId,
  };
}

/** Rebind the store to a new daemon/project/session identity, clearing pending uploads. */
export function rebindReferenceUploadStore(
  store: ReferenceUploadStore,
  identity: { daemonInstanceId: string; projectId: string; sessionId: string },
  options: { cleanupSandboxCopy?: (uri: string) => void } = {},
): ReferenceUploadStore {
  const cleared = clearPendingUploads(store, options);
  return {
    ...cleared,
    daemonInstanceId: identity.daemonInstanceId,
    projectId: identity.projectId,
    sessionId: identity.sessionId,
  };
}

// ---------------------------------------------------------------------------
// Selection replacement
// ---------------------------------------------------------------------------

/** Replace the current selection with a new one, retiring the prior upload. */
export function replaceSelection(
  store: ReferenceUploadStore,
  priorUploadId: string,
  source: ReferenceSelectionSource,
  options: {
    abortTransport?: (uploadId: string) => void;
    cleanupSandboxCopy?: (uri: string) => void;
  } = {},
): ReferenceUploadRecord | null {
  // Retire the prior upload (gets a new ID/epoch; cannot duplicate-bind the old result).
  cancelUpload(store, priorUploadId, {
    abortTransport: options.abortTransport,
    cleanupSandboxCopy: options.cleanupSandboxCopy,
  });
  return beginSelection(store, source);
}

// ---------------------------------------------------------------------------
// Ignored late results
// ---------------------------------------------------------------------------

/** Returns `true` if a late completion for a retired upload should be ignored. */
export function shouldIgnoreLateCompletion(
  store: ReferenceUploadStore,
  uploadId: string,
  selectionEpoch: number,
  identity: { daemonInstanceId: string; projectId: string; sessionId: string },
): boolean {
  const record = store.uploads.get(uploadId);
  if (!record) return true;
  if (record.state === "cancelled" || record.state === "failed") return true;
  if (selectionEpoch < record.selectionEpoch) return true;
  if (!identityMatches(store, identity)) return true;
  if (
    record.daemonInstanceId !== identity.daemonInstanceId ||
    record.projectId !== identity.projectId ||
    record.sessionId !== identity.sessionId
  ) {
    return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Accessors
// ---------------------------------------------------------------------------

/** Active (non-terminal) uploads. */
export function activeUploads(store: ReferenceUploadStore): ReferenceUploadRecord[] {
  return [...store.uploads.values()].filter((record) => !isTerminalUploadState(record.state));
}

/** Completed uploads with opaque attachment handles ready for planning. */
export function completedUploads(store: ReferenceUploadStore): ReferenceUploadRecord[] {
  return [...store.uploads.values()].filter(
    (record) => record.state === "completed" && record.attachmentHandle !== null,
  );
}

/** Count of completed uploads for the current session. */
export function completedUploadCount(store: ReferenceUploadStore): number {
  return completedUploads(store).length;
}

/** Returns `true` if adding another reference would exceed the session limit. */
export function wouldExceedSessionLimit(
  store: ReferenceUploadStore,
  limits: ReferenceMediaLimits = DEFAULT_REFERENCE_MEDIA_LIMITS,
): boolean {
  return completedUploadCount(store) >= limits.maxReferencesPerSession;
}

// ---------------------------------------------------------------------------
// Error contract: distinct recovery
// ---------------------------------------------------------------------------

/** The distinct recovery error codes for picker/upload failures. */
export type ReferenceUploadErrorCode =
  | "picker_canceled"
  | "permission_denied"
  | "icloud_remote_asset_download"
  | "lost_background_network"
  | "storage_exhausted"
  | "checksum_failure"
  | "share_unavailable"
  | "revoked_artifact"
  | "unsupported_media_kind"
  | "byte_length_out_of_range"
  | "invalid_dimensions"
  | "width_exceeds_limit"
  | "height_exceeds_limit"
  | "upload_failed"
  | "host_path_reauthorization_required";

/** A stable recovery message for each error code, without leaking inaccessible metadata. */
export function referenceUploadRecoveryMessage(code: ReferenceUploadErrorCode): string {
  switch (code) {
    case "picker_canceled":
      return "Selection canceled.";
    case "permission_denied":
      return "Permission denied. Grant photo library access in Settings to attach references.";
    case "icloud_remote_asset_download":
      return "The selected asset is in iCloud. Download it to your device first, then attach it.";
    case "lost_background_network":
      return "Network was lost during upload. Retry when you have a stable connection.";
    case "storage_exhausted":
      return "Device storage is full. Free up space before attaching references.";
    case "checksum_failure":
      return "The uploaded file did not match its checksum. Retry the selection.";
    case "share_unavailable":
      return "Sharing is not available on this device.";
    case "revoked_artifact":
      return "The artifact was revoked and is no longer available.";
    case "unsupported_media_kind":
      return "This file type is not supported. Use PNG, JPEG, WebP, or SVG.";
    case "byte_length_out_of_range":
      return "The file is too large. Use a smaller reference.";
    case "invalid_dimensions":
      return "The image has invalid dimensions.";
    case "width_exceeds_limit":
      return "The image is too wide.";
    case "height_exceeds_limit":
      return "The image is too tall.";
    case "upload_failed":
      return "Upload failed. Retry the selection.";
    case "host_path_reauthorization_required":
      return "The destination path requires reauthorization. Contact the project owner.";
  }
}

/** Returns `true` if picker cancellation is a normal no-op (not an error). */
export function isPickerCancellationNormal(code: ReferenceUploadErrorCode): boolean {
  return code === "picker_canceled";
}
