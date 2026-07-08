import { buttonVariants } from "@flycockpit/ui/components/button";
import { Link, useRouterState } from "@tanstack/react-router";
import { TerminalSquare } from "lucide-react";
import { useTranslation } from "react-i18next";
import { DEFAULT_LOCALE, isSupportedLocale } from "@/i18n/config";
import { useLiveTerminalStore } from "@/stores/live-terminal";

export function LiveTerminalBanner() {
  const terminals = useLiveTerminalStore((s) => s.terminals);
  const lang = useRouterState({
    select: (state) => {
      const segment = state.location.pathname.split("/")[1];
      return isSupportedLocale(segment) ? segment : DEFAULT_LOCALE;
    },
  });
  const { t } = useTranslation("instances");
  const terminal = terminals[0];
  if (!terminal) return null;

  return (
    <div className="border-b border-amber-500/30 bg-amber-500/10 px-4 py-2 text-amber-950 dark:text-amber-100">
      <div className="container mx-auto flex min-h-[44px] flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex min-w-0 items-center gap-2 text-sm font-medium">
          <TerminalSquare className="size-4 shrink-0" />
          <span className="truncate">
            {t("terminal.liveBanner", { name: terminal.instanceName, count: terminals.length })}
          </span>
        </div>
        <Link
          to="/$lang/instances/$instanceId/terminal"
          params={{ lang, instanceId: terminal.instanceId }}
          className={buttonVariants({
            variant: "outline",
            size: "sm",
            className: "min-h-[36px] bg-background/80",
          })}
        >
          {t("terminal.returnToTerminal")}
        </Link>
      </div>
    </div>
  );
}
