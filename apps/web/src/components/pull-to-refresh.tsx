import { Loader2 } from "lucide-react";
import { useCallback, useRef, useState } from "react";

interface PullToRefreshProps {
  onRefresh: () => Promise<void>;
  children: React.ReactNode;
}

const THRESHOLD = 80;
const MAX_PULL = 128;

export default function PullToRefresh({ onRefresh, children }: PullToRefreshProps) {
  const [refreshing, setRefreshing] = useState(false);
  const touchStartY = useRef(0);
  const pulling = useRef(false);
  const pullDistanceRef = useRef(0);
  const containerRef = useRef<HTMLDivElement>(null);
  const indicatorRef = useRef<HTMLDivElement>(null);
  const iconRef = useRef<SVGSVGElement>(null);

  function updateIndicator(distance: number) {
    const indicator = indicatorRef.current;
    const icon = iconRef.current;
    if (!indicator || !icon) return;
    const progress = Math.min(distance / THRESHOLD, 1);
    indicator.style.height = distance > 0 ? `${distance}px` : "0";
    Object.assign(icon.style, {
      opacity: String(progress),
      transform: `rotate(${progress * 360}deg)`,
    });
  }

  const handleTouchStart = useCallback(
    (e: React.TouchEvent) => {
      const container = containerRef.current;
      if (!container || container.scrollTop > 0 || refreshing) return;
      touchStartY.current = e.touches[0].clientY;
      pulling.current = true;
      if (indicatorRef.current) {
        indicatorRef.current.style.transitionDuration = "0ms";
      }
    },
    [refreshing],
  );

  const handleTouchMove = useCallback((e: React.TouchEvent) => {
    if (!pulling.current) return;
    const delta = e.touches[0].clientY - touchStartY.current;
    if (delta < 0) {
      pulling.current = false;
      pullDistanceRef.current = 0;
      updateIndicator(0);
      return;
    }
    const dampened = Math.min(delta * 0.5, MAX_PULL);
    pullDistanceRef.current = dampened;
    updateIndicator(dampened);
  }, []);

  const handleTouchEnd = useCallback(async () => {
    if (!pulling.current && pullDistanceRef.current === 0) return;
    pulling.current = false;

    if (indicatorRef.current) {
      indicatorRef.current.style.transitionDuration = "200ms";
    }

    if (pullDistanceRef.current >= THRESHOLD) {
      setRefreshing(true);
      pullDistanceRef.current = THRESHOLD / 2;
      updateIndicator(THRESHOLD / 2);
      if (iconRef.current) {
        iconRef.current.style.animation = "spin 0.8s linear infinite";
      }
      try {
        await onRefresh();
      } finally {
        setRefreshing(false);
        pullDistanceRef.current = 0;
        updateIndicator(0);
        if (iconRef.current) {
          iconRef.current.style.animation = "none";
        }
      }
    } else {
      pullDistanceRef.current = 0;
      updateIndicator(0);
    }
  }, [onRefresh]);

  return (
    <div
      ref={containerRef}
      className="relative h-full overflow-y-auto"
      onTouchStart={handleTouchStart}
      onTouchMove={handleTouchMove}
      onTouchEnd={handleTouchEnd}
    >
      <div
        ref={indicatorRef}
        className="flex items-center justify-center overflow-hidden transition-[height] duration-200"
        style={{ height: 0 }}
      >
        <Loader2 ref={iconRef} className="size-5 text-muted-foreground" style={{ opacity: 0 }} />
      </div>
      {children}
    </div>
  );
}
