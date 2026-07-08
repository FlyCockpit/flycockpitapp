import { Button } from "@flycockpit/ui/components/button";
import { cn } from "@flycockpit/ui/lib/utils";
import { useTranslation } from "react-i18next";

type InlineRetryProps = {
  message?: string;
  onRetry: () => void;
  variant?: "muted" | "destructive";
  className?: string;
};

export function InlineRetry({ message, onRetry, variant = "muted", className }: InlineRetryProps) {
  const { t } = useTranslation("common");
  const text = message ?? t("somethingWentWrong");

  if (variant === "destructive") {
    return (
      <div
        className={cn(
          "rounded-md border border-destructive/30 bg-destructive/5 p-4 text-sm",
          className,
        )}
      >
        <p className="font-medium text-destructive">{text}</p>
        <Button variant="outline" size="sm" className="mt-2 min-h-[44px]" onClick={onRetry}>
          {t("actions.tryAgain")}
        </Button>
      </div>
    );
  }

  return (
    <div
      className={cn("flex flex-col items-center justify-center gap-3 py-8 text-center", className)}
    >
      <p className="text-sm text-muted-foreground">{text}</p>
      <Button variant="outline" size="sm" onClick={onRetry} className="min-h-[44px]">
        {t("actions.tryAgain")}
      </Button>
    </div>
  );
}
