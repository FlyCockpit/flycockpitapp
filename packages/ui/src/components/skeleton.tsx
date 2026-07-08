import { cn } from "@flycockpit/ui/lib/utils";

type SkeletonProps = React.ComponentProps<"div"> & {
  variant?: "pulse" | "shimmer";
};

function Skeleton({ className, variant = "pulse", ...props }: SkeletonProps) {
  return (
    <div
      data-slot="skeleton"
      className={cn(
        "rounded-md bg-muted",
        variant === "pulse" ? "animate-pulse" : "skeleton-shimmer",
        className,
      )}
      {...props}
    />
  );
}

export { Skeleton };
