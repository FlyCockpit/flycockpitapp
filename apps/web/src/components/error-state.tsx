import { Button } from "@flycockpit/ui/components/button";
import type { ErrorComponentProps } from "@tanstack/react-router";
import { AlertTriangle } from "lucide-react";
import { useTranslation } from "react-i18next";

import { friendly } from "../utils/friendly-error";

export default function ErrorState({ error, reset }: ErrorComponentProps) {
  const { t } = useTranslation(["common", "errors"]);
  return (
    <div className="flex h-full flex-col items-center justify-center gap-3 px-6 py-8 text-center">
      <AlertTriangle className="size-8 text-destructive" />
      <div className="space-y-1">
        <p className="text-base font-medium">{t("common:somethingWentWrong")}</p>
        <p className="text-sm text-muted-foreground break-words">
          {friendly(error, t("errors:rootError"))}
        </p>
      </div>
      <div className="mt-2 flex flex-wrap items-center justify-center gap-2">
        <Button onClick={reset} variant="outline" className="min-h-[44px]">
          {t("common:actions.tryAgain")}
        </Button>
        <Button onClick={() => window.location.reload()} className="min-h-[44px]">
          {t("common:actions.reload")}
        </Button>
      </div>
    </div>
  );
}
