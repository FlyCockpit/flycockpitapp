import { cn } from "@flycockpit/ui/lib/utils";
import * as React from "react";

type StaggerProps = React.ComponentProps<"div"> & {
  as?: React.ElementType;
  childClassName?: string;
  childVariant?: "fade" | "slide-up" | "slide-down" | "scale" | "pop";
  stepMs?: number;
};

const staggerChildVariants = {
  fade: "animate-in fade-in-0",
  "slide-up": "animate-in fade-in-0 slide-in-from-bottom-2",
  "slide-down": "animate-in fade-in-0 slide-in-from-top-2",
  scale: "animate-in fade-in-0 zoom-in-95",
  pop: "animate-in fade-in-0 zoom-in-95 ease-spring",
} as const;

function Stagger({
  as,
  children,
  childClassName,
  childVariant = "slide-up",
  className,
  stepMs = 50,
  style,
  ...props
}: StaggerProps) {
  const Component = as ?? "div";

  return (
    <Component
      data-slot="stagger"
      className={className}
      style={
        {
          "--stagger-step": `${stepMs}ms`,
          ...style,
        } as React.CSSProperties & { "--stagger-step": string }
      }
      {...props}
    >
      {React.Children.map(children, (child, index) => {
        if (child === null || child === undefined || typeof child === "boolean") {
          return child;
        }

        return (
          <div
            data-slot="stagger-item"
            className={cn(
              "duration-[var(--duration-base)] fill-mode-both ease-out",
              staggerChildVariants[childVariant],
              childClassName,
            )}
            style={{
              animationDelay: `calc(var(--stagger-step) * ${index})`,
              animationDuration: "var(--duration-base)",
              animationFillMode: "both",
              animationTimingFunction:
                childVariant === "pop" ? "var(--ease-spring)" : "var(--ease-out)",
            }}
          >
            {child}
          </div>
        );
      })}
    </Component>
  );
}

export { Stagger };
