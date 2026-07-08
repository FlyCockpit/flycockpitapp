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
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@flycockpit/ui/components/dialog";
import { Skeleton } from "@flycockpit/ui/components/skeleton";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute, Link } from "@tanstack/react-router";
import { Plus, Video } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { InlineRetry } from "@/components/inline-retry";
import { VideoUploader } from "@/components/video/uploader";
import { orpc } from "@/utils/orpc";

export const Route = createFileRoute("/$lang/admin/videos/")({
  component: AdminVideos,
});

type VideoStatus = "PENDING" | "TRANSCODING" | "READY" | "FAILED";

const STATUS_TONE: Record<VideoStatus, string> = {
  PENDING: "bg-muted text-muted-foreground",
  TRANSCODING: "bg-yellow-500/10 text-yellow-700 dark:text-yellow-300",
  READY: "bg-emerald-500/10 text-emerald-700 dark:text-emerald-300",
  FAILED: "bg-destructive/10 text-destructive",
};

const STATUS_LABEL_KEY: Record<VideoStatus, string> = {
  PENDING: "videos:list.statusPending",
  TRANSCODING: "videos:list.statusTranscoding",
  READY: "videos:list.statusReady",
  FAILED: "videos:list.statusFailed",
};

function AdminVideos() {
  const { lang } = Route.useParams();
  const { t } = useTranslation(["videos", "common"]);
  const [uploadOpen, setUploadOpen] = useState(false);
  const queryClient = useQueryClient();

  const videos = useQuery(orpc.videos.list.queryOptions({ input: { limit: 50 } }));

  return (
    <div className="container mx-auto max-w-7xl px-4 py-8 space-y-6">
      <header className="flex items-center justify-between">
        <div className="space-y-1">
          <h1 className="text-2xl font-semibold tracking-tight">{t("videos:list.title")}</h1>
        </div>
        <Button onClick={() => setUploadOpen(true)} className="min-h-[44px]">
          <Plus className="size-4 mr-2" aria-hidden />
          {t("videos:list.uploadCta")}
        </Button>
      </header>

      {videos.isPending ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {Array.from({ length: 6 }).map((_, i) => (
            <Skeleton key={i} className="h-40 w-full" />
          ))}
        </div>
      ) : videos.isError ? (
        <Card>
          <CardContent>
            <InlineRetry onRetry={() => videos.refetch()} />
          </CardContent>
        </Card>
      ) : videos.data && videos.data.items.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center space-y-3">
            <Video className="size-12 mx-auto text-muted-foreground" aria-hidden />
            <p className="text-sm text-muted-foreground">{t("videos:list.empty")}</p>
            <Button onClick={() => setUploadOpen(true)}>{t("videos:list.uploadCta")}</Button>
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {videos.data?.items.map((video) => (
            <Link
              key={video.id}
              to="/$lang/admin/videos/$videoId"
              params={{ lang, videoId: video.id }}
              className="block"
            >
              <Card className="hover:bg-muted/30 transition-colors">
                <CardHeader>
                  <div className="flex items-start justify-between gap-2">
                    <CardTitle className="text-base truncate">{video.title}</CardTitle>
                    <span
                      className={`inline-flex shrink-0 items-center rounded-md px-2 py-0.5 text-xs ${
                        STATUS_TONE[video.status as VideoStatus] ?? STATUS_TONE.PENDING
                      }`}
                    >
                      {t(STATUS_LABEL_KEY[video.status as VideoStatus] ?? STATUS_LABEL_KEY.PENDING)}
                    </span>
                  </div>
                  {video.description ? (
                    <CardDescription className="line-clamp-2">{video.description}</CardDescription>
                  ) : null}
                </CardHeader>
                {video.status === "READY" ? (
                  <CardContent>
                    <div className="aspect-video rounded-md bg-muted overflow-hidden">
                      <img
                        src={video.posterUrl}
                        alt=""
                        className="w-full h-full object-cover"
                        loading="lazy"
                      />
                    </div>
                  </CardContent>
                ) : null}
              </Card>
            </Link>
          ))}
        </div>
      )}

      <Dialog
        open={uploadOpen}
        onOpenChange={(open) => {
          setUploadOpen(open);
          if (!open) {
            queryClient.invalidateQueries({ queryKey: orpc.videos.list.key() });
          }
        }}
      >
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>{t("videos:list.uploadCta")}</DialogTitle>
            <DialogDescription>{t("videos:detail.transcodingHint")}</DialogDescription>
          </DialogHeader>
          <VideoUploader
            onUploaded={() => {
              setUploadOpen(false);
              queryClient.invalidateQueries({ queryKey: orpc.videos.list.key() });
            }}
          />
        </DialogContent>
      </Dialog>
    </div>
  );
}
