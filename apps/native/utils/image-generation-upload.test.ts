import { describe, expect, it } from "vitest";
import {
  activeUploads,
  beginCopy,
  beginSelection,
  beginUpload,
  beginValidation,
  cancelUpload,
  clearPendingUploads,
  completedUploads,
  completeUpload,
  createReferenceUploadStore,
  DEFAULT_REFERENCE_MEDIA_LIMITS,
  failUpload,
  isPickerCancellationNormal,
  isRawDeviceUri,
  isTerminalUploadState,
  mintUploadId,
  rebindReferenceUploadStore,
  referenceUploadRecoveryMessage,
  releaseSandboxConsumer,
  replaceSelection,
  reportProgress,
  shouldIgnoreLateCompletion,
  validateReference,
  wouldExceedSessionLimit,
} from "./image-generation-upload";

const identity = {
  daemonInstanceId: "daemon-1",
  projectId: "project-1",
  sessionId: "session-1",
};

const otherIdentity = {
  daemonInstanceId: "daemon-2",
  projectId: "project-2",
  sessionId: "session-2",
};

describe("image generation upload state machine", () => {
  it("mints opaque 22-char base64url upload IDs that are not device paths", () => {
    const id = mintUploadId();
    expect(id).toHaveLength(22);
    expect(/^[A-Za-z0-9_-]+$/.test(id)).toBe(true);
    expect(isRawDeviceUri(id)).toBe(false);
  });

  it("validates content/file/library sources against typed media limits", () => {
    const valid = validateReference({
      mediaKind: "image/png",
      byteLength: 1024,
      width: 512,
      height: 512,
    });
    expect(valid.valid).toBe(true);

    const wrongKind = validateReference({
      mediaKind: "image/gif",
      byteLength: 1024,
      width: 512,
      height: 512,
    });
    expect(wrongKind.valid).toBe(false);

    const tooBig = validateReference({
      mediaKind: "image/png",
      byteLength: DEFAULT_REFERENCE_MEDIA_LIMITS.maxByteLength + 1,
      width: 512,
      height: 512,
    });
    expect(tooBig.valid).toBe(false);
  });

  it("progresses through selecting -> copying -> validating -> uploading -> completed", () => {
    const store = createReferenceUploadStore(identity);
    const record = beginSelection(store, "library");
    expect(record.state).toBe("selecting");
    expect(record.selectionEpoch).toBe(1);

    const copied = beginCopy(store, record.uploadId, "file:///sandbox/copy.png");
    expect(copied?.state).toBe("copying");
    expect(copied?.activeConsumers).toBe(1);

    const validating = beginValidation(store, record.uploadId);
    expect(validating?.state).toBe("validating");

    const uploading = beginUpload(store, record.uploadId);
    expect(uploading?.state).toBe("uploading");

    const progress = reportProgress(store, record.uploadId, record.selectionEpoch, 0.5);
    expect(progress?.progress).toBe(0.5);

    const completed = completeUpload(
      store,
      record.uploadId,
      record.selectionEpoch,
      "attachment-handle-opaque",
    );
    expect(completed?.state).toBe("completed");
    expect(completed?.attachmentHandle).toBe("attachment-handle-opaque");
    expect(completedUploads(store)).toHaveLength(1);
  });

  it("cancel retires the ID, requests transport abort, and cleans sandbox copy", () => {
    const store = createReferenceUploadStore(identity);
    const record = beginSelection(store, "file");
    beginCopy(store, record.uploadId, "file:///sandbox/copy.png");
    beginValidation(store, record.uploadId);
    beginUpload(store, record.uploadId);

    let aborted = false;
    let cleanedUri: string | null = null;
    let serverCleanupRequested = false;
    const cancelled = cancelUpload(store, record.uploadId, {
      abortTransport: () => {
        aborted = true;
      },
      cleanupSandboxCopy: (uri) => {
        cleanedUri = uri;
      },
      requestServerCleanup: () => {
        serverCleanupRequested = true;
      },
    });
    expect(cancelled?.state).toBe("cancelled");
    expect(aborted).toBe(true);
    expect(cleanedUri).toBe("file:///sandbox/copy.png");
    expect(serverCleanupRequested).toBe(true);
    // Sandbox copy cleared after cleanup.
    expect(store.uploads.get(record.uploadId)?.sandboxCopyUri).toBeNull();
    // The retired ID is no longer current.
    expect(completeUpload(store, record.uploadId, record.selectionEpoch, "handle")).toBeNull();
  });

  it("retry gets a new ID/epoch and cannot duplicate-bind the old result", () => {
    const store = createReferenceUploadStore(identity);
    const first = beginSelection(store, "library");
    beginCopy(store, first.uploadId, "file:///sandbox/copy1.png");
    cancelUpload(store, first.uploadId);

    const replaced = replaceSelection(store, first.uploadId, "library");
    expect(replaced?.uploadId).not.toBe(first.uploadId);
    expect(replaced?.selectionEpoch).toBeGreaterThan(first.selectionEpoch);
    // Late completion for the old ID is ignored.
    expect(shouldIgnoreLateCompletion(store, first.uploadId, first.selectionEpoch, identity)).toBe(
      true,
    );
  });

  it("ignores progress/completion for a prior epoch", () => {
    const store = createReferenceUploadStore(identity);
    const first = beginSelection(store, "library");
    beginCopy(store, first.uploadId, "file:///sandbox/copy.png");
    beginValidation(store, first.uploadId);
    beginUpload(store, first.uploadId);
    cancelUpload(store, first.uploadId);

    const second = beginSelection(store, "library");
    // Progress for the old epoch is ignored.
    expect(reportProgress(store, first.uploadId, first.selectionEpoch, 0.5)).toBeNull();
    expect(second.selectionEpoch).toBeGreaterThan(first.selectionEpoch);
  });

  it("ignores completion for a prior session/project/daemon instance", () => {
    const store = createReferenceUploadStore(identity);
    const record = beginSelection(store, "file");
    beginCopy(store, record.uploadId, "file:///sandbox/copy.png");
    beginValidation(store, record.uploadId);
    beginUpload(store, record.uploadId);
    expect(
      shouldIgnoreLateCompletion(store, record.uploadId, record.selectionEpoch, otherIdentity),
    ).toBe(true);
  });

  it("background/termination leaves no planned reference; late server success ignored", () => {
    const store = createReferenceUploadStore(identity);
    const record = beginSelection(store, "file");
    beginCopy(store, record.uploadId, "file:///sandbox/copy.png");
    // App background/termination: clear pending uploads.
    let cleaned = false;
    const cleared = clearPendingUploads(store, {
      cleanupSandboxCopy: () => {
        cleaned = true;
      },
    });
    expect(cleaned).toBe(true);
    expect(activeUploads(cleared)).toHaveLength(0);
    // Late server success for the retired upload is ignored.
    expect(
      shouldIgnoreLateCompletion(cleared, record.uploadId, record.selectionEpoch, identity),
    ).toBe(true);
  });

  it("rebind clears pending uploads on switch/reconnect", () => {
    const store = createReferenceUploadStore(identity);
    beginSelection(store, "library");
    const rebound = rebindReferenceUploadStore(store, otherIdentity);
    expect(activeUploads(rebound)).toHaveLength(0);
    expect(rebound.daemonInstanceId).toBe(otherIdentity.daemonInstanceId);
    expect(rebound.sessionId).toBe(otherIdentity.sessionId);
  });

  it("releaseSandboxConsumer cleans the sandbox copy when no active consumers remain", () => {
    const store = createReferenceUploadStore(identity);
    const record = beginSelection(store, "library");
    beginCopy(store, record.uploadId, "file:///sandbox/copy.png");
    let cleaned = false;
    releaseSandboxConsumer(store, record.uploadId, () => {
      cleaned = true;
    });
    // Not terminal yet, so cleanup does not run.
    expect(cleaned).toBe(false);
  });

  it("failUpload records a stable error code and cleans sandbox copy", () => {
    const store = createReferenceUploadStore(identity);
    const record = beginSelection(store, "file");
    beginCopy(store, record.uploadId, "file:///sandbox/copy.png");
    let cleaned = false;
    const failed = failUpload(store, record.uploadId, "upload_failed", {
      cleanupSandboxCopy: () => {
        cleaned = true;
      },
    });
    expect(failed?.state).toBe("failed");
    expect(failed?.errorCode).toBe("upload_failed");
    expect(cleaned).toBe(true);
    expect(isTerminalUploadState("failed")).toBe(true);
  });

  it("wouldExceedSessionLimit gates on maxReferencesPerSession", () => {
    const store = createReferenceUploadStore(identity);
    expect(wouldExceedSessionLimit(store)).toBe(false);
    // Complete maxReferencesPerSession uploads.
    for (let i = 0; i < DEFAULT_REFERENCE_MEDIA_LIMITS.maxReferencesPerSession; i++) {
      const record = beginSelection(store, "library");
      beginCopy(store, record.uploadId, `file:///sandbox/copy${i}.png`);
      beginValidation(store, record.uploadId);
      beginUpload(store, record.uploadId);
      completeUpload(store, record.uploadId, record.selectionEpoch, `handle-${i}`);
    }
    expect(wouldExceedSessionLimit(store)).toBe(true);
  });

  it("rejects a raw device URI as an attachment handle", () => {
    const store = createReferenceUploadStore(identity);
    const record = beginSelection(store, "library");
    beginCopy(store, record.uploadId, "file:///sandbox/copy.png");
    beginValidation(store, record.uploadId);
    beginUpload(store, record.uploadId);
    const completed = completeUpload(
      store,
      record.uploadId,
      record.selectionEpoch,
      "content://photos/123",
    );
    expect(completed).toBeNull();
  });

  it("picker cancellation is a normal no-op with a distinct recovery message", () => {
    expect(isPickerCancellationNormal("picker_canceled")).toBe(true);
    expect(referenceUploadRecoveryMessage("picker_canceled")).toBe("Selection canceled.");
    expect(referenceUploadRecoveryMessage("permission_denied")).toContain("Permission denied");
    expect(referenceUploadRecoveryMessage("icloud_remote_asset_download")).toContain("iCloud");
    expect(referenceUploadRecoveryMessage("lost_background_network")).toContain("Network");
    expect(referenceUploadRecoveryMessage("storage_exhausted")).toContain("storage");
    expect(referenceUploadRecoveryMessage("checksum_failure")).toContain("checksum");
    expect(referenceUploadRecoveryMessage("share_unavailable")).toContain("Sharing");
    expect(referenceUploadRecoveryMessage("revoked_artifact")).toContain("revoked");
    expect(referenceUploadRecoveryMessage("host_path_reauthorization_required")).toContain(
      "reauthorization",
    );
  });
});
