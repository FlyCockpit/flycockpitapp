import { Button } from "@flycockpit/ui/components/button";
import { useQuery } from "@tanstack/react-query";
import { AlertTriangle } from "lucide-react";
import { Trans, useTranslation } from "react-i18next";

import { useAuthSessionSnapshot } from "@/hooks/use-auth-session";
import { orpc } from "@/utils/orpc";

/**
 * Renders a prominent warning when ADMIN_EMAILS is unset on the server. A
 * fresh deploy with no admins configured cannot grant admin privileges to
 * anyone, and the existing console-level warning is easy for nontechnical
 * owners to miss. This banner surfaces that condition in the UI itself.
 *
 * Renders nothing while loading so it never flashes during pending state.
 * Query errors render a conservative warning because this check protects the
 * admin bootstrap path.
 */
export function AdminSetupBanner() {
  const { t } = useTranslation("admin");
  // adminSetupStatus is a protectedProcedure — calling it while logged out
  // returns 401, which would render the error banner to every anonymous
  // visitor (it mounts in __root). Gate the query on an authenticated session
  // so the banner only ever shows to logged-in users (its intended audience).
  const { data: session, isPending: sessionPending } = useAuthSessionSnapshot();
  // ADMIN_EMAILS is a server-restart-time constant, so refetching on every
  // route transition is wasteful. 5-minute staleTime avoids hammering the API.
  const { data, isPending, isError, refetch } = useQuery({
    ...orpc.settings.adminSetupStatus.queryOptions(),
    enabled: !!session,
    staleTime: 5 * 60 * 1000,
  });

  if (sessionPending || !session) return null;
  if (isPending) return null;
  if (isError) {
    return (
      <div
        role="alert"
        className="border-b border-yellow-300 bg-yellow-100 px-4 py-3 text-sm text-yellow-900 dark:border-yellow-700 dark:bg-yellow-950 dark:text-yellow-100"
      >
        <div className="flex flex-col gap-3 sm:flex-row sm:items-start">
          <AlertTriangle className="mt-0.5 size-5 shrink-0" aria-hidden="true" />
          <div className="flex-1 space-y-1">
            <p className="font-medium">{t("setupBanner.errorTitle")}</p>
            <p className="text-yellow-900/90 dark:text-yellow-100/90">
              {t("setupBanner.errorMessage")}
            </p>
          </div>
          <Button variant="outline" size="sm" className="min-h-[44px]" onClick={() => refetch()}>
            {t("setupBanner.retry")}
          </Button>
        </div>
      </div>
    );
  }
  if (!data?.adminEmailsEmpty) return null;

  return (
    <div
      role="alert"
      className="border-b border-yellow-300 bg-yellow-100 px-4 py-3 text-sm text-yellow-900 dark:border-yellow-700 dark:bg-yellow-950 dark:text-yellow-100"
    >
      <div className="flex items-start gap-3">
        <AlertTriangle className="mt-0.5 size-5 shrink-0" aria-hidden="true" />
        <div className="flex-1 space-y-1">
          <p className="font-medium">{t("setupBanner.title")}</p>
          <p className="text-yellow-900/90 dark:text-yellow-100/90">
            <Trans
              i18nKey="setupBanner.message"
              t={t}
              components={[<code key="0" className="font-mono" />]}
            />
          </p>
        </div>
      </div>
    </div>
  );
}
