import { uploadVideo } from "@flycockpit/api/lib/video-client";
import { isSupportedLocale, SUPPORTED_LOCALES } from "@flycockpit/config/locales";
import { Button } from "@flycockpit/ui/components/button";
import { useMutation } from "@tanstack/react-query";
import { Loader2, Upload, X } from "lucide-react";
import { useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import { client as orpcClient } from "@/utils/orpc";

/**
 * Drag-and-drop video upload. Wraps `uploadVideo()` from the API package and
 * surfaces progress + cancel. Calls back with the new videoId so the caller
 * can navigate to the watch/admin route.
 *
 * Touch targets follow the PWA rule (min-h-[44px]). i18n strings live under
 * the `videos` namespace.
 */

export type VideoUploaderProps = {
  /** Defaults to the active i18n locale. */
  defaultSourceLocale?: string;
  defaultVisibility?: "PUBLIC" | "RESTRICTED";
  onUploaded: (videoId: string) => void;
};

export function VideoUploader({
  defaultSourceLocale,
  defaultVisibility = "RESTRICTED",
  onUploaded,
}: VideoUploaderProps) {
  const { i18n, t } = useTranslation(["videos", "common"]);
  const [file, setFile] = useState<File | null>(null);
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [sourceLocale, setSourceLocale] = useState<string>(() => {
    const candidate = defaultSourceLocale ?? i18n.language;
    return isSupportedLocale(candidate) ? candidate : SUPPORTED_LOCALES[0];
  });
  const [visibility, setVisibility] = useState<"PUBLIC" | "RESTRICTED">(defaultVisibility);
  const [progress, setProgress] = useState(0);
  const abortRef = useRef<AbortController | null>(null);
  const inputRef = useRef<HTMLInputElement | null>(null);

  const upload = useMutation({
    mutationFn: async () => {
      if (!file) throw new Error(t("videos:uploader.missingFile"));
      if (!title.trim()) throw new Error(t("videos:uploader.missingTitle"));
      abortRef.current = new AbortController();
      return uploadVideo({
        file,
        title: title.trim(),
        description: description.trim() || null,
        visibility,
        sourceLocale,
        onProgress: setProgress,
        signal: abortRef.current.signal,
        rpc: {
          start: (input) => orpcClient.videos.start(input),
          presignParts: (input) => orpcClient.videos.presignParts(input),
          complete: (input) => orpcClient.videos.complete(input),
          abort: (input) => orpcClient.videos.abort(input),
          heartbeat: (input) => orpcClient.videos.heartbeat(input),
        },
      });
    },
    onSuccess: (result) => {
      onUploaded(result.videoId);
      reset();
    },
  });

  function reset() {
    setFile(null);
    setTitle("");
    setDescription("");
    setProgress(0);
    abortRef.current = null;
    if (inputRef.current) inputRef.current.value = "";
  }

  function onPick(picked: File | null) {
    setFile(picked);
    if (picked && !title.trim()) {
      // Pre-fill title from filename minus extension as a kindness.
      const base = picked.name.replace(/\.[^.]+$/, "");
      setTitle(base);
    }
  }

  function onDrop(e: React.DragEvent<HTMLDivElement>) {
    e.preventDefault();
    if (upload.isPending) return;
    const dropped = e.dataTransfer.files?.[0];
    if (dropped?.type.startsWith("video/")) {
      onPick(dropped);
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <div
        onDragOver={(e) => e.preventDefault()}
        onDrop={onDrop}
        onClick={() => !upload.isPending && inputRef.current?.click()}
        className="rounded-lg border-2 border-dashed border-border p-8 text-center cursor-pointer hover:border-foreground/50 transition-colors min-h-[160px] flex flex-col items-center justify-center gap-2"
        role="button"
        tabIndex={0}
        onKeyDown={(e) => {
          if ((e.key === "Enter" || e.key === " ") && !upload.isPending) {
            inputRef.current?.click();
          }
        }}
      >
        <Upload className="size-8 text-muted-foreground" aria-hidden />
        <div className="text-sm">
          {file ? (
            <span className="font-medium">{file.name}</span>
          ) : (
            <>
              <span className="font-medium">{t("videos:uploader.dropOrClick")}</span>
              <span className="ml-1 text-muted-foreground">
                {t("videos:uploader.acceptedFormats")}
              </span>
            </>
          )}
        </div>
        <input
          ref={inputRef}
          type="file"
          accept="video/*"
          className="hidden"
          onChange={(e) => onPick(e.target.files?.[0] ?? null)}
          disabled={upload.isPending}
        />
      </div>

      <label className="flex flex-col gap-1.5">
        <span className="text-sm font-medium">{t("videos:uploader.titleLabel")}</span>
        <input
          type="text"
          value={title}
          onChange={(e) => setTitle(e.target.value)}
          disabled={upload.isPending}
          maxLength={200}
          className="min-h-[44px] rounded-md border border-input bg-background px-3 py-2 text-sm"
          autoComplete="off"
        />
      </label>

      <label className="flex flex-col gap-1.5">
        <span className="text-sm font-medium">{t("videos:uploader.descriptionLabel")}</span>
        <textarea
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          disabled={upload.isPending}
          maxLength={2000}
          rows={3}
          className="rounded-md border border-input bg-background px-3 py-2 text-sm"
        />
      </label>

      <div className="grid grid-cols-2 gap-3">
        <label className="flex flex-col gap-1.5">
          <span className="text-sm font-medium">{t("videos:uploader.sourceLocaleLabel")}</span>
          <select
            value={sourceLocale}
            onChange={(e) => setSourceLocale(e.target.value)}
            disabled={upload.isPending}
            className="min-h-[44px] rounded-md border border-input bg-background px-3 py-2 text-sm"
          >
            {SUPPORTED_LOCALES.map((locale) => (
              <option key={locale} value={locale}>
                {locale}
              </option>
            ))}
          </select>
        </label>
        <label className="flex flex-col gap-1.5">
          <span className="text-sm font-medium">{t("videos:uploader.visibilityLabel")}</span>
          <select
            value={visibility}
            onChange={(e) => setVisibility(e.target.value as "PUBLIC" | "RESTRICTED")}
            disabled={upload.isPending}
            className="min-h-[44px] rounded-md border border-input bg-background px-3 py-2 text-sm"
          >
            <option value="RESTRICTED">{t("videos:uploader.visibilityRestricted")}</option>
            <option value="PUBLIC">{t("videos:uploader.visibilityPublic")}</option>
          </select>
        </label>
      </div>

      {upload.isPending && (
        <div className="space-y-1.5">
          <div className="h-2 w-full rounded-full bg-muted overflow-hidden">
            <div
              className="h-full bg-primary transition-[width] duration-200 ease-out"
              style={{ width: `${Math.round(progress * 100)}%` }}
            />
          </div>
          <p className="text-xs text-muted-foreground">
            {t("videos:uploader.progress", { percent: Math.round(progress * 100) })}
          </p>
        </div>
      )}

      {upload.isError && (
        <p className="text-sm text-destructive">
          {upload.error instanceof Error ? upload.error.message : t("common:somethingWentWrong")}
        </p>
      )}

      <div className="flex items-center gap-2">
        <Button
          type="button"
          onClick={() => upload.mutate()}
          disabled={!file || !title.trim() || upload.isPending}
          className="min-h-[44px]"
        >
          {upload.isPending ? (
            <>
              <Loader2 className="size-4 mr-2 animate-spin" aria-hidden />
              {t("videos:uploader.uploading")}
            </>
          ) : (
            t("videos:uploader.startUpload")
          )}
        </Button>
        {upload.isPending && (
          <Button
            type="button"
            variant="ghost"
            onClick={() => abortRef.current?.abort()}
            className="min-h-[44px]"
          >
            <X className="size-4 mr-2" aria-hidden />
            {t("common:actions.cancel")}
          </Button>
        )}
      </div>
    </div>
  );
}
