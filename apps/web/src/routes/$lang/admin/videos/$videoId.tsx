import { uploadAudioTrack } from "@flycockpit/api/lib/video-client";
import { isSupportedLocale, SUPPORTED_LOCALES } from "@flycockpit/config/locales";
import { Button } from "@flycockpit/ui/components/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@flycockpit/ui/components/card";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@flycockpit/ui/components/dialog";
import { toast } from "@flycockpit/ui/components/sileo";
import { Skeleton } from "@flycockpit/ui/components/skeleton";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { ArrowLeft, RefreshCw, Trash2, Upload } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { ConfirmDeleteDialog } from "@/components/confirm-delete-dialog";
import { InlineRetry } from "@/components/inline-retry";
import { VideoPlayer } from "@/components/video/player";
import { orpc, client as orpcClient } from "@/utils/orpc";

export const Route = createFileRoute("/$lang/admin/videos/$videoId")({
  component: AdminVideoDetail,
});

function AdminVideoDetail() {
  const { lang, videoId } = Route.useParams();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { t } = useTranslation(["videos", "common"]);

  const video = useQuery(orpc.videos.get.queryOptions({ input: { id: videoId } }));
  const [addAudioOpen, setAddAudioOpen] = useState(false);
  const [addSubtitleOpen, setAddSubtitleOpen] = useState(false);
  const [deleteOpen, setDeleteOpen] = useState(false);

  const reprocess = useMutation({
    ...orpc.videos.adminReprocess.mutationOptions(),
    onSuccess: () => {
      toast.success(t("videos:admin.reprocessed"));
      queryClient.invalidateQueries({ queryKey: orpc.videos.get.key({ input: { id: videoId } }) });
    },
  });

  const del = useMutation({
    ...orpc.videos.delete.mutationOptions(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: orpc.videos.list.key() });
      navigate({ to: "/$lang/admin/videos", params: { lang } });
    },
  });

  if (video.isPending) {
    return (
      <div className="container mx-auto max-w-5xl px-4 py-8">
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  if (video.isError || !video.data) {
    return (
      <div className="container mx-auto max-w-5xl px-4">
        <InlineRetry onRetry={() => video.refetch()} />
      </div>
    );
  }

  const data = video.data;

  return (
    <div className="container mx-auto max-w-5xl px-4 py-8 space-y-6">
      <div className="flex items-center justify-between gap-2">
        <Link
          to="/$lang/admin/videos"
          params={{ lang }}
          className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
        >
          <ArrowLeft className="size-4" aria-hidden />
          {t("common:actions.back")}
        </Link>
        <div className="flex items-center gap-2">
          {data.status === "FAILED" ? (
            <Button
              variant="outline"
              onClick={() => reprocess.mutate({ id: videoId })}
              disabled={reprocess.isPending}
              className="min-h-[44px]"
            >
              <RefreshCw className="size-4 mr-2" aria-hidden />
              {t("videos:admin.reprocess")}
            </Button>
          ) : null}
          <Button
            variant="destructive"
            onClick={() => setDeleteOpen(true)}
            className="min-h-[44px]"
          >
            <Trash2 className="size-4 mr-2" aria-hidden />
            {t("videos:detail.deleteVideo")}
          </Button>
        </div>
      </div>

      <header className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">{data.title}</h1>
        {data.description ? (
          <p className="text-sm text-muted-foreground">{data.description}</p>
        ) : null}
      </header>

      {data.status === "READY" ? (
        <div className="rounded-lg overflow-hidden border">
          <VideoPlayer
            videoId={data.id}
            title={data.title}
            playlistUrl={data.playlistUrl}
            posterUrl={data.posterUrl}
            thumbnailsUrl={data.thumbnailsUrl}
            subtitleTracks={data.subtitleTracks.map((s) => ({
              id: s.id,
              locale: s.locale,
              label: s.label,
              kind: s.kind,
              url: s.url,
            }))}
            preferredSubtitleLocale={data.sourceLocale}
          />
        </div>
      ) : data.status === "FAILED" ? (
        <Card>
          <CardContent className="py-6">
            <p className="text-sm text-destructive">
              {t("videos:detail.failedHint", {
                reason: data.failureReason ?? t("common:somethingWentWrong"),
              })}
            </p>
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardContent className="py-6">
            <p className="text-sm text-muted-foreground">{t("videos:detail.transcodingHint")}</p>
          </CardContent>
        </Card>
      )}

      <section className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between gap-2">
              <CardTitle className="text-base">{t("videos:detail.audioTracksHeading")}</CardTitle>
              <Button
                size="sm"
                variant="outline"
                className="min-h-[44px]"
                onClick={() => setAddAudioOpen(true)}
                disabled={data.status !== "READY"}
              >
                <Upload className="size-3 mr-1" aria-hidden />
                {t("videos:detail.addAudioTrack")}
              </Button>
            </div>
            <CardDescription>{data.sourceLocale}</CardDescription>
          </CardHeader>
          <CardContent>
            {data.audioTracks.length === 0 ? null : (
              <ul className="space-y-2">
                {data.audioTracks.map((a) => (
                  <li key={a.id} className="flex items-center justify-between text-sm">
                    <span>
                      <span className="font-medium">{a.label}</span>
                      <span className="text-muted-foreground"> · {a.locale}</span>
                      {a.isDefault ? (
                        <span className="ml-2 text-xs text-muted-foreground">
                          {t("videos:detail.defaultTrack")}
                        </span>
                      ) : null}
                    </span>
                    <span className="text-xs text-muted-foreground">{a.status}</span>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <div className="flex items-center justify-between gap-2">
              <CardTitle className="text-base">
                {t("videos:detail.subtitleTracksHeading")}
              </CardTitle>
              <Button
                size="sm"
                variant="outline"
                className="min-h-[44px]"
                onClick={() => setAddSubtitleOpen(true)}
              >
                <Upload className="size-3 mr-1" aria-hidden />
                {t("videos:detail.addSubtitleTrack")}
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            {data.subtitleTracks.length === 0 ? null : (
              <ul className="space-y-2">
                {data.subtitleTracks.map((s) => (
                  <li key={s.id} className="flex items-center justify-between text-sm">
                    <span>
                      <span className="font-medium">{s.label}</span>
                      <span className="text-muted-foreground"> · {s.locale}</span>
                    </span>
                    <span className="text-xs text-muted-foreground">{s.kind}</span>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>

        <Card className="md:col-span-2">
          <CardHeader>
            <CardTitle className="text-base">{t("videos:detail.renditionsHeading")}</CardTitle>
          </CardHeader>
          <CardContent>
            {data.renditions.length === 0 ? (
              <p className="text-sm text-muted-foreground">—</p>
            ) : (
              <ul className="flex flex-wrap gap-2 text-xs">
                {data.renditions.map((r) => (
                  <li key={r.height} className="rounded-md bg-muted px-2 py-1">
                    {r.height}p · {Math.round(r.bandwidth / 1000)} kbps
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>
      </section>

      <AddAudioDialog
        open={addAudioOpen}
        onOpenChange={setAddAudioOpen}
        videoId={videoId}
        existingLocales={data.audioTracks.map((a) => a.locale)}
        sourceLocale={data.sourceLocale}
      />
      <AddSubtitleDialog
        open={addSubtitleOpen}
        onOpenChange={setAddSubtitleOpen}
        videoId={videoId}
      />

      <ConfirmDeleteDialog
        open={deleteOpen}
        onOpenChange={setDeleteOpen}
        title={t("videos:detail.deleteVideo")}
        description={data.title}
        confirmToken={data.title}
        typePrompt={t("videos:detail.deleteVideoConfirm")}
        copyAriaLabel={t("common:actions.copy")}
        isPending={del.isPending}
        onConfirm={() => del.mutate({ id: videoId })}
      />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Add audio dub
// ---------------------------------------------------------------------------

function AddAudioDialog(props: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  videoId: string;
  existingLocales: string[];
  sourceLocale: string;
}) {
  const queryClient = useQueryClient();
  const { t } = useTranslation(["videos", "common"]);
  const [locale, setLocale] = useState<string>("");
  const [label, setLabel] = useState("");
  const [file, setFile] = useState<File | null>(null);

  const availableLocales = SUPPORTED_LOCALES.filter(
    (l) => l !== props.sourceLocale && !props.existingLocales.includes(l),
  );

  const upload = useMutation({
    mutationFn: async () => {
      if (!file) throw new Error(t("videos:uploader.missingAudioFile"));
      if (!isSupportedLocale(locale)) throw new Error(t("videos:uploader.missingLocale"));

      return uploadAudioTrack({
        videoId: props.videoId,
        locale,
        label: label.trim() || locale,
        file,
        rpc: {
          startAudioTrack: (input) => orpcClient.videos.startAudioTrack(input),
          presignAudioTrackParts: (input) => orpcClient.videos.presignAudioTrackParts(input),
          finalizeAudioTrack: (input) => orpcClient.videos.finalizeAudioTrack(input),
          abortAudioTrack: (input) => orpcClient.videos.abortAudioTrack(input),
          heartbeatAudioTrack: (input) => orpcClient.videos.heartbeatAudioTrack(input),
        },
      });
    },
    onSuccess: () => {
      props.onOpenChange(false);
      setFile(null);
      setLabel("");
      setLocale("");
      queryClient.invalidateQueries({
        queryKey: orpc.videos.get.key({ input: { id: props.videoId } }),
      });
    },
  });

  return (
    <Dialog open={props.open} onOpenChange={props.onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t("videos:detail.addAudioTrack")}</DialogTitle>
        </DialogHeader>
        <div className="space-y-3">
          <label className="flex flex-col gap-1.5">
            <span className="text-sm font-medium">{t("videos:uploader.sourceLocaleLabel")}</span>
            <select
              value={locale}
              onChange={(e) => setLocale(e.target.value)}
              className="min-h-[44px] rounded-md border border-input bg-background px-3 py-2 text-sm"
              disabled={upload.isPending}
            >
              <option value="">—</option>
              {availableLocales.map((l) => (
                <option key={l} value={l}>
                  {l}
                </option>
              ))}
            </select>
          </label>
          <label className="flex flex-col gap-1.5">
            <span className="text-sm font-medium">{t("videos:detail.trackLabel")}</span>
            <input
              type="text"
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              disabled={upload.isPending}
              className="min-h-[44px] rounded-md border border-input bg-background px-3 py-2 text-sm"
            />
          </label>
          <input
            type="file"
            accept="audio/*,video/*"
            onChange={(e) => setFile(e.target.files?.[0] ?? null)}
            disabled={upload.isPending}
          />
          {upload.isError ? (
            <p className="text-sm text-destructive">
              {upload.error instanceof Error
                ? upload.error.message
                : t("common:somethingWentWrong")}
            </p>
          ) : null}
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => props.onOpenChange(false)}>
            {t("common:actions.cancel")}
          </Button>
          <Button onClick={() => upload.mutate()} disabled={!file || !locale || upload.isPending}>
            {upload.isPending ? t("videos:uploader.uploading") : t("common:actions.save")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ---------------------------------------------------------------------------
// Add subtitle track
// ---------------------------------------------------------------------------

function AddSubtitleDialog(props: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  videoId: string;
}) {
  const queryClient = useQueryClient();
  const { t } = useTranslation(["videos", "common"]);
  const [locale, setLocale] = useState<string>("");
  const [label, setLabel] = useState("");
  const [content, setContent] = useState("");
  const [format, setFormat] = useState<"vtt" | "srt">("vtt");

  const submit = useMutation({
    ...orpc.videos.addSubtitleTrack.mutationOptions(),
    onSuccess: () => {
      props.onOpenChange(false);
      setContent("");
      setLocale("");
      setLabel("");
      queryClient.invalidateQueries({
        queryKey: orpc.videos.get.key({ input: { id: props.videoId } }),
      });
    },
  });

  return (
    <Dialog open={props.open} onOpenChange={props.onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t("videos:detail.addSubtitleTrack")}</DialogTitle>
        </DialogHeader>
        <div className="space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <label className="flex flex-col gap-1.5">
              <span className="text-sm font-medium">{t("videos:uploader.sourceLocaleLabel")}</span>
              <select
                value={locale}
                onChange={(e) => setLocale(e.target.value)}
                className="min-h-[44px] rounded-md border border-input bg-background px-3 py-2 text-sm"
              >
                <option value="">—</option>
                {SUPPORTED_LOCALES.map((l) => (
                  <option key={l} value={l}>
                    {l}
                  </option>
                ))}
              </select>
            </label>
            <label className="flex flex-col gap-1.5">
              <span className="text-sm font-medium">{t("videos:detail.subtitleFormat")}</span>
              <select
                value={format}
                onChange={(e) => setFormat(e.target.value as "vtt" | "srt")}
                className="min-h-[44px] rounded-md border border-input bg-background px-3 py-2 text-sm"
              >
                <option value="vtt">WebVTT</option>
                <option value="srt">SRT</option>
              </select>
            </label>
          </div>
          <label className="flex flex-col gap-1.5">
            <span className="text-sm font-medium">{t("videos:detail.trackLabel")}</span>
            <input
              type="text"
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              className="min-h-[44px] rounded-md border border-input bg-background px-3 py-2 text-sm"
            />
          </label>
          <label className="flex flex-col gap-1.5">
            <span className="text-sm font-medium">{t("videos:detail.subtitleContent")}</span>
            <textarea
              value={content}
              onChange={(e) => setContent(e.target.value)}
              rows={8}
              className="rounded-md border border-input bg-background px-3 py-2 text-sm font-mono"
              placeholder={
                format === "vtt"
                  ? t("videos:detail.vttPlaceholder")
                  : t("videos:detail.srtPlaceholder")
              }
            />
          </label>
          {submit.isError ? (
            <p className="text-sm text-destructive">
              {submit.error instanceof Error
                ? submit.error.message
                : t("common:somethingWentWrong")}
            </p>
          ) : null}
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => props.onOpenChange(false)}>
            {t("common:actions.cancel")}
          </Button>
          <Button
            onClick={() =>
              submit.mutate({
                videoId: props.videoId,
                locale,
                label: label.trim() || locale,
                kind: "SUBTITLES",
                isDefault: false,
                content,
                format,
              })
            }
            disabled={!locale || !content.trim() || submit.isPending}
          >
            {t("common:actions.save")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
