/**
 * DOM attachment tray for the browser media composer.
 *
 * Accepts paste, drag/drop, and a keyboard-operable file picker for the
 * exact image/audio/video format matrix owned by the daemon. Plain-text
 * paste remains ordinary text. Drop is active only over the labeled
 * composer drop target and never navigates the page.
 *
 * The browser never decodes a selected/raw local image and never creates
 * an Object URL, ImageBitmap, <img> source, canvas, or thumbnail from the
 * raw File. Before authoritative `ready` it shows only safe
 * filename/declared size/status.
 */

import { Button } from "@flycockpit/ui/components/button";
import { AlertTriangle, LoaderCircle, Paperclip, RotateCw, X } from "lucide-react";
import { type KeyboardEvent, useCallback, useId, useRef } from "react";
import { useTranslation } from "react-i18next";
import {
  type MediaDraft,
  type MediaDraftItem,
  type MediaItemState,
  type MediaKind,
  SUPPORTED_MIME_BY_KIND,
} from "@/lib/web-media-draft-reducer";

// ---------------------------------------------------------------------------
// View model
// ---------------------------------------------------------------------------

/** One row in the attachment tray, derived from the typed reducer state. */
export interface MediaTrayRow {
  itemId: string;
  kind: MediaKind;
  fileName: string;
  declaredSize: number;
  state: MediaItemState;
  uploadedBytes: number;
  acknowledgedBytes: number;
  error: string | null;
  retryCursor: string | null;
  previewUrl: string | null;
  requiresLocalBytes: boolean;
  isTerminal: boolean;
  canRetry: boolean;
  canCancel: boolean;
  canRemove: boolean;
  /** True when the item is in an indeterminate (non-progress) state. */
  indeterminate: boolean;
  /** Progress fraction 0..1, or null for indeterminate. */
  progress: number | null;
}

/**
 * Derives the visible tray view model from the typed reducer state.
 * One typed view model drives the tray and accessibility state.
 */
export function deriveTrayRows(draft: MediaDraft | undefined): MediaTrayRow[] {
  if (!draft) return [];
  return draft.items.map((item) => deriveTrayRow(item));
}

function deriveTrayRow(item: MediaDraftItem): MediaTrayRow {
  const isTerminal = item.state === "failed" && item.retryCursor === "terminal";
  const canRetry = item.state === "failed" && !isTerminal;
  const canCancel =
    item.state !== "sent" &&
    item.state !== "cancelled" &&
    item.state !== "cancelling" &&
    item.state !== "removing";
  const canRemove = item.state === "ready";
  const indeterminate =
    item.state === "processing" ||
    item.state === "recovering" ||
    item.state === "cancelling" ||
    item.state === "removing" ||
    item.state === "beginning" ||
    item.state === "finalizing" ||
    item.state === "queued" ||
    item.state === "hashing";
  const progress =
    item.state === "uploading" && item.declaredSize > 0
      ? Math.min(1, item.uploadedBytes / item.declaredSize)
      : null;
  return {
    itemId: item.itemId,
    kind: item.kind,
    fileName: item.fileName,
    declaredSize: item.declaredSize,
    state: item.state,
    uploadedBytes: item.uploadedBytes,
    acknowledgedBytes: item.acknowledgedBytes,
    error: item.error,
    retryCursor: item.retryCursor,
    previewUrl: item.previewUrl,
    requiresLocalBytes: item.requiresLocalBytes,
    isTerminal,
    canRetry,
    canCancel,
    canRemove,
    indeterminate,
    progress,
  };
}

// ---------------------------------------------------------------------------
// Status label key
// ---------------------------------------------------------------------------

function statusKey(state: MediaItemState): string {
  return `instances:remote.mediaAttachmentStatus.${state}`;
}

// ---------------------------------------------------------------------------
// Component props
// ---------------------------------------------------------------------------

export interface MediaAttachmentTrayProps {
  /** The current session draft, or undefined when no session is selected. */
  draft: MediaDraft | undefined;
  /** Whether the viewer can write (Owner/Writer). Readonly sees a disabled control. */
  canWrite: boolean;
  /** Called when files are picked, dropped, or pasted. */
  onAddFiles: (files: File[]) => void;
  /** Called when the user requests removal of a ready item. */
  onRemove: (itemId: string) => void;
  /** Called when the user requests cancellation of an item. */
  onCancel: (itemId: string) => void;
  /** Called when the user requests retry of a failed item. */
  onRetry: (itemId: string) => void;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function MediaAttachmentTray({
  draft,
  canWrite,
  onAddFiles,
  onRemove,
  onCancel,
  onRetry,
}: MediaAttachmentTrayProps) {
  const { t } = useTranslation("instances");
  const fileInputRef = useRef<HTMLInputElement>(null);
  const dropTargetId = useId();
  const rows = deriveTrayRows(draft);

  const handleFileSelect = useCallback(
    (event: React.ChangeEvent<HTMLInputElement>) => {
      if (!canWrite) return;
      const files = Array.from(event.target.files ?? []);
      if (files.length > 0) onAddFiles(files);
      // Reset the input so the same file can be selected again.
      event.target.value = "";
    },
    [canWrite, onAddFiles],
  );

  const handleKeyDown = useCallback(
    (event: KeyboardEvent) => {
      if (!canWrite) return;
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        fileInputRef.current?.click();
      }
    },
    [canWrite],
  );

  const handleDrop = useCallback(
    (event: React.DragEvent) => {
      if (!canWrite) return;
      event.preventDefault();
      event.stopPropagation();
      const files = Array.from(event.dataTransfer.files);
      if (files.length > 0) onAddFiles(files);
    },
    [canWrite, onAddFiles],
  );

  const handleDragOver = useCallback(
    (event: React.DragEvent) => {
      if (!canWrite) return;
      event.preventDefault();
      event.stopPropagation();
    },
    [canWrite],
  );

  const acceptAttr = Object.values(SUPPORTED_MIME_BY_KIND).flat().join(",");

  if (!canWrite) {
    // Readonly sees a disabled attachment control and cannot cause file
    // read, hashing, begin, or enumeration through leaked IDs.
    return null;
  }

  return (
    <div
      className="space-y-2"
      role="region"
      aria-label={t("instances:remote.mediaAttachmentTrayLabel")}
    >
      {/* Labeled drop target / file picker */}
      <div
        id={dropTargetId}
        role="button"
        tabIndex={0}
        aria-label={t("instances:remote.mediaAttachmentDropTarget")}
        aria-describedby={`${dropTargetId}-hint`}
        className="flex items-center gap-2 rounded-md border border-dashed px-3 py-2 text-sm text-muted-foreground cursor-pointer hover:bg-muted/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        onClick={() => fileInputRef.current?.click()}
        onKeyDown={handleKeyDown}
        onDrop={handleDrop}
        onDragOver={handleDragOver}
        onDragEnter={handleDragOver}
      >
        <Paperclip className="size-4" />
        <span>{t("instances:remote.mediaAttachmentDropTarget")}</span>
        <input
          ref={fileInputRef}
          type="file"
          multiple
          accept={acceptAttr}
          className="sr-only"
          onChange={handleFileSelect}
          aria-label={t("instances:remote.mediaAttachmentAddButtonAriaLabel")}
        />
      </div>
      <span id={`${dropTargetId}-hint`} className="sr-only">
        {t("instances:remote.mediaAttachmentDropTarget")}
      </span>

      {/* Tray rows */}
      {rows.length > 0 ? (
        <ul className="space-y-1" aria-label={t("instances:remote.mediaAttachmentTrayLabel")}>
          {rows.map((row) => (
            <MediaTrayRowView
              key={row.itemId}
              row={row}
              t={t}
              onRemove={onRemove}
              onCancel={onCancel}
              onRetry={onRetry}
            />
          ))}
        </ul>
      ) : null}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Row component
// ---------------------------------------------------------------------------

interface MediaTrayRowViewProps {
  row: MediaTrayRow;
  t: (key: string, options?: Record<string, unknown>) => string;
  onRemove: (itemId: string) => void;
  onCancel: (itemId: string) => void;
  onRetry: (itemId: string) => void;
}

function MediaTrayRowView({ row, t, onRemove, onCancel, onRetry }: MediaTrayRowViewProps) {
  const statusLabel = t(statusKey(row.state));
  const showError = row.state === "failed" && row.error;
  const showProgress = row.progress !== null && row.progress < 1;

  return (
    <li className="flex items-center gap-2 rounded-md border px-3 py-2 text-sm" aria-live="polite">
      {/* Preview: only daemon-validated Blob URLs for ready images */}
      {row.previewUrl && row.state === "ready" ? (
        <img
          src={row.previewUrl}
          alt={t("instances:remote.mediaAttachmentPreviewAlt", { name: row.fileName })}
          className="size-10 shrink-0 rounded object-cover"
        />
      ) : (
        <Paperclip className="size-4 shrink-0 text-muted-foreground" />
      )}

      {/* Filename and status */}
      <div className="min-w-0 flex-1">
        <div className="truncate font-medium">{row.fileName}</div>
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          {row.indeterminate ? (
            <LoaderCircle className="size-3 animate-spin" aria-hidden="true" />
          ) : null}
          <span>{statusLabel}</span>
          {showProgress ? (
            <span>
              {t("instances:remote.mediaAttachmentProgress", {
                uploaded: row.uploadedBytes,
                total: row.declaredSize,
              })}
            </span>
          ) : null}
        </div>
        {showError ? (
          <div className="mt-1 flex items-start gap-1 text-xs text-destructive">
            <AlertTriangle className="mt-0.5 size-3 shrink-0" />
            <span>
              {row.isTerminal
                ? t("instances:remote.mediaAttachmentTerminalFailure")
                : row.retryCursor === "query_attachment_status" && row.error === "local_bytes_lost"
                  ? t("instances:remote.mediaAttachmentLocalBytesLost")
                  : row.error}
            </span>
          </div>
        ) : null}
      </div>

      {/* Actions */}
      <div className="flex shrink-0 items-center gap-1">
        {row.canRetry ? (
          <Button
            type="button"
            size="sm"
            variant="ghost"
            aria-label={t("instances:remote.mediaAttachmentRetry")}
            onClick={() => onRetry(row.itemId)}
          >
            <RotateCw className="size-3" />
          </Button>
        ) : null}
        {row.canCancel ? (
          <Button
            type="button"
            size="sm"
            variant="ghost"
            aria-label={t("instances:remote.mediaAttachmentCancel")}
            onClick={() => onCancel(row.itemId)}
          >
            <X className="size-3" />
          </Button>
        ) : null}
        {row.canRemove ? (
          <Button
            type="button"
            size="sm"
            variant="ghost"
            aria-label={t("instances:remote.mediaAttachmentRemove")}
            onClick={() => onRemove(row.itemId)}
          >
            <X className="size-3" />
          </Button>
        ) : null}
      </div>
    </li>
  );
}

// ---------------------------------------------------------------------------
// Before-unload warning helper
// ---------------------------------------------------------------------------

/**
 * Returns true when a beforeunload warning should be shown — exactly when
 * any item has `requiresLocalBytes=true`.
 */
export function shouldWarnBeforeUnload(draft: MediaDraft | undefined): boolean {
  if (!draft) return false;
  return draft.items.some((item) => item.requiresLocalBytes);
}

// ---------------------------------------------------------------------------
// Keyboard reorder helper
// ---------------------------------------------------------------------------

/**
 * Handles keyboard reorder of tray items. Returns the new item ID order
 * after moving the focused item up or down.
 */
export function keyboardReorder(
  items: MediaDraftItem[],
  focusedItemId: string,
  direction: "up" | "down",
): string[] {
  const index = items.findIndex((item) => item.itemId === focusedItemId);
  if (index === -1) return items.map((item) => item.itemId);
  const swapIndex = direction === "up" ? index - 1 : index + 1;
  if (swapIndex < 0 || swapIndex >= items.length) return items.map((item) => item.itemId);
  const ids = items.map((item) => item.itemId);
  [ids[index], ids[swapIndex]] = [ids[swapIndex]!, ids[index]!];
  return ids;
}
