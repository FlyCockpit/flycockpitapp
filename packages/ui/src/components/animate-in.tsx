import { cn } from "@flycockpit/ui/lib/utils";
import * as React from "react";

const animateInVariants = {
  fade: "animate-in fade-in-0",
  "slide-up": "animate-in fade-in-0 slide-in-from-bottom-2",
  "slide-down": "animate-in fade-in-0 slide-in-from-top-2",
  scale: "animate-in fade-in-0 zoom-in-95",
  pop: "animate-in fade-in-0 zoom-in-95 ease-spring",
} as const;

type AnimateInVariant = keyof typeof animateInVariants;

type AnimateInProps = React.ComponentProps<"div"> & {
  variant?: AnimateInVariant;
  as?: React.ElementType;
};

function AnimateIn({ as, className, style, variant = "fade", ...props }: AnimateInProps) {
  const Component = as ?? "div";

  return (
    <Component
      data-slot="animate-in"
      className={cn(
        "duration-[var(--duration-base)] fill-mode-both ease-out",
        animateInVariants[variant],
        className,
      )}
      style={{
        animationDuration: "var(--duration-base)",
        animationFillMode: "both",
        animationTimingFunction: variant === "pop" ? "var(--ease-spring)" : "var(--ease-out)",
        ...style,
      }}
      {...props}
    />
  );
}

export { AnimateIn };
