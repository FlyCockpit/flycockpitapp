import { Card, CardContent } from "@flycockpit/ui/components/card";
import { Skeleton } from "@flycockpit/ui/components/skeleton";
import { useQuery } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";

import { InlineRetry } from "@/components/inline-retry";
import { VideoPlayer } from "@/components/video/player";
import { orpc } from "@/utils/orpc";

/**
 * Public watch route. Visibility enforcement lives in the oRPC `videos.get`
 * procedure (which calls `authorizeVideoRead`) — a RESTRICTED video for a
 * non-owner returns NOT_FOUND, and the page renders a generic "unavailable"
 * message rather than disclosing that the video exists.
 */
export const Route = createFileRoute("/$lang/videos/$videoId")({
  component: WatchVideo,
});

function WatchVideo() {
  const { videoId, lang } = Route.useParams();
  const { t } = useTranslation(["videos", "common"]);

  const video = useQuery(orpc.videos.get.queryOptions({ input: { id: videoId } }));

  if (video.isPending) {
    return (
      <div className="container mx-auto max-w-4xl px-4 py-6">
        <Skeleton className="aspect-video w-full" />
      </div>
    );
  }
  if (video.isError && !isNotFoundError(video.error)) {
    return (
      <div className="container mx-auto max-w-4xl px-4 py-6">
        <InlineRetry onRetry={() => video.refetch()} />
      </div>
    );
  }

  if (video.isError || !video.data) {
    return (
      <div className="container mx-auto max-w-4xl px-4 py-6">
        <Card>
          <CardContent className="py-10 text-center">
            <p className="text-sm text-muted-foreground">{t("videos:watch.playerUnavailable")}</p>
          </CardContent>
        </Card>
      </div>
    );
  }

  const data = video.data;
  if (data.status !== "READY") {
    return (
      <div className="container mx-auto max-w-4xl px-4 py-6">
        <Card>
          <CardContent className="py-10 text-center">
            <p className="text-sm text-muted-foreground">{t("videos:detail.transcodingHint")}</p>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="container mx-auto max-w-4xl px-4 py-6 space-y-4">
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
          preferredSubtitleLocale={lang}
        />
      </div>
      <header>
        <h1 className="text-xl font-semibold">{data.title}</h1>
        {data.description ? (
          <p className="mt-2 text-sm text-muted-foreground whitespace-pre-line">
            {data.description}
          </p>
        ) : null}
      </header>
    </div>
  );
}

function isNotFoundError(error: unknown): boolean {
  if (!error || typeof error !== "object") return false;
  const shape = error as { code?: unknown; status?: unknown };
  return shape.code === "NOT_FOUND" || shape.status === 404;
}
