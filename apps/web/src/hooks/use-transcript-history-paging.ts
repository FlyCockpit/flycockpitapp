import { useCallback, useRef } from "react";
import { anchoredScrollTop, shouldLoadOlderHistory } from "@/lib/scroll-anchor";

export function useTranscriptHistoryPaging(input: {
  anchorKey: string | null;
  hasMore: boolean;
  isLoading: boolean;
  onLoadOlder: () => Promise<void>;
}) {
  const { anchorKey, hasMore, isLoading, onLoadOlder } = input;
  const containerRef = useRef<HTMLDivElement | null>(null);
  const pendingRef = useRef(false);
  const anchorKeyRef = useRef(anchorKey);
  anchorKeyRef.current = anchorKey;

  const loadOlderWithAnchor = useCallback(async () => {
    const container = containerRef.current;
    if (!container || !hasMore || isLoading || pendingRef.current) return;

    pendingRef.current = true;
    const requestAnchorKey = anchorKeyRef.current;
    const previousScrollHeight = container.scrollHeight;
    const previousScrollTop = container.scrollTop;
    try {
      await onLoadOlder();
      window.requestAnimationFrame(() => {
        const current = containerRef.current;
        if (!current || anchorKeyRef.current !== requestAnchorKey) return;
        current.scrollTop = anchoredScrollTop({
          previousScrollHeight,
          previousScrollTop,
          nextScrollHeight: current.scrollHeight,
        });
      });
    } finally {
      pendingRef.current = false;
    }
  }, [hasMore, isLoading, onLoadOlder]);

  const onScroll = useCallback(() => {
    const container = containerRef.current;
    if (!container || !shouldLoadOlderHistory({ scrollTop: container.scrollTop })) return;
    void loadOlderWithAnchor();
  }, [loadOlderWithAnchor]);

  return { containerRef, loadOlderWithAnchor, onScroll };
}
