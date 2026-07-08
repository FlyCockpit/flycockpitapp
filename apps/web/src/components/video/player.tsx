import "@vidstack/react/player/styles/default/theme.css";
import "@vidstack/react/player/styles/default/layouts/video.css";

import { MediaPlayer, type MediaPlayerInstance, MediaProvider, Track } from "@vidstack/react";
import { DefaultVideoLayout, defaultLayoutIcons } from "@vidstack/react/player/layouts/default";
import { useRef } from "react";

/**
 * HLS video player built on Vidstack. Vidstack uses hls.js under the hood for
 * browsers that don't support HLS natively (everything except Safari) and
 * exposes a React component surface so we don't have to reinvent multi-audio
 * switching, subtitle UI, sprite-sheet thumbnail previews, or keyboard a11y.
 *
 * Why Vidstack over bare hls.js + <video>: hover previews from a WebVTT
 * thumbnail track, audio-language switching, subtitle styling, and
 * keyboard-controlled scrubbing are non-trivial to build correctly from
 * scratch. Vidstack ships them all, with ~80kb gz. The dep is removable —
 * see the video module notes for swap instructions.
 *
 * The component is intentionally thin — it accepts the same shape the oRPC
 * `videos.get` procedure returns, plus a few presentation-only props. No
 * data fetching inside; pass the resolved video.
 */

type VideoPlayerSubtitleTrack = {
  id: string;
  locale: string;
  label: string;
  kind: "SUBTITLES" | "CAPTIONS" | "DESCRIPTIONS";
  url: string;
};

export type VideoPlayerProps = {
  videoId: string;
  title: string;
  playlistUrl: string;
  posterUrl?: string;
  thumbnailsUrl?: string;
  subtitleTracks?: VideoPlayerSubtitleTrack[];
  /** BCP 47 — preselects the matching subtitle track on mount. */
  preferredSubtitleLocale?: string;
  /** Autoplay only works after user gesture in modern browsers — opt-in. */
  autoPlay?: boolean;
  className?: string;
  onEnded?: () => void;
};

export function VideoPlayer(props: VideoPlayerProps) {
  const playerRef = useRef<MediaPlayerInstance | null>(null);

  // Match the player's track-kind names. Vidstack accepts `subtitles` /
  // `captions` / `descriptions` (lowercase).
  const kindMap: Record<
    VideoPlayerSubtitleTrack["kind"],
    "subtitles" | "captions" | "descriptions"
  > = {
    SUBTITLES: "subtitles",
    CAPTIONS: "captions",
    DESCRIPTIONS: "descriptions",
  };

  return (
    <MediaPlayer
      ref={playerRef}
      src={{ src: props.playlistUrl, type: "application/vnd.apple.mpegurl" }}
      poster={props.posterUrl}
      title={props.title}
      crossOrigin
      playsInline
      autoPlay={props.autoPlay}
      onEnded={props.onEnded}
      streamType="on-demand"
      className={props.className}
    >
      <MediaProvider>
        {props.subtitleTracks?.map((track) => (
          <Track
            key={track.id}
            src={track.url}
            kind={kindMap[track.kind]}
            label={track.label}
            lang={track.locale}
            default={track.locale === props.preferredSubtitleLocale}
          />
        ))}
      </MediaProvider>
      <DefaultVideoLayout icons={defaultLayoutIcons} thumbnails={props.thumbnailsUrl} />
    </MediaPlayer>
  );
}
