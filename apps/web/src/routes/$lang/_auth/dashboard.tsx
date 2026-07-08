import { env } from "@flycockpit/env/web";
import { Skeleton } from "@flycockpit/ui/components/skeleton";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import { useCallback } from "react";
import { useTranslation } from "react-i18next";

import { InlineRetry } from "@/components/inline-retry";
import PullToRefresh from "@/components/pull-to-refresh";
import { orpc } from "@/utils/orpc";

export const Route = createFileRoute("/$lang/_auth/dashboard")({
  component: DashboardPage,
});

function DashboardPage() {
  const { session } = Route.useRouteContext();
  const queryClient = useQueryClient();
  const appSettings = useQuery(orpc.settings.getAll.queryOptions());
  const { t } = useTranslation(["common", "dashboard"]);
  const appName = env.VITE_APP_NAME;

  const handleRefresh = useCallback(async () => {
    await queryClient.invalidateQueries();
  }, [queryClient]);

  return (
    <PullToRefresh onRefresh={handleRefresh}>
      <div className="container mx-auto max-w-4xl px-4 py-8">
        {appSettings.isPending ? (
          <DashboardSkeleton />
        ) : appSettings.isError ? (
          <InlineRetry
            className="py-12"
            message={t("dashboard:loadFailed")}
            onRetry={() => appSettings.refetch()}
          />
        ) : (
          <>
            <h1 className="text-2xl font-semibold">
              {t("common:welcome")} {t("common:appName", { name: appName })}
            </h1>
            <p className="mt-2 text-muted-foreground">
              {t("dashboard:welcomeBack", { name: session.user.name })}
            </p>
          </>
        )}
      </div>
    </PullToRefresh>
  );
}

function DashboardSkeleton() {
  return (
    <div className="space-y-4">
      <Skeleton className="h-8 w-48" />
      <Skeleton className="h-5 w-64" />
    </div>
  );
}
