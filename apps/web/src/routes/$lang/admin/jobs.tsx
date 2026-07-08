import { Button } from "@flycockpit/ui/components/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@flycockpit/ui/components/card";
import { Skeleton } from "@flycockpit/ui/components/skeleton";
import { useQuery } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import { CheckCircle2, RefreshCcw } from "lucide-react";
import { useMemo } from "react";
import { useTranslation } from "react-i18next";

import { InlineRetry } from "@/components/inline-retry";
import { orpc } from "@/utils/orpc";

export const Route = createFileRoute("/$lang/admin/jobs")({
  component: AdminJobsPage,
});

function AdminJobsPage() {
  const { i18n, t } = useTranslation(["admin", "common"]);
  const dateFormatter = useMemo(
    () => new Intl.DateTimeFormat(i18n.language, { dateStyle: "medium", timeStyle: "short" }),
    [i18n.language],
  );
  const failedJobs = useQuery(
    orpc.queue.listFailed.queryOptions({
      input: { limit: 50 },
      refetchInterval: 30_000,
    }),
  );
  const failedJobsDescription = failedJobs.isPending
    ? t("admin:common.loading")
    : failedJobs.isError
      ? t("admin:common.loadFailed")
      : failedJobs.data.items.length >= 50
        ? t("admin:jobs.failedCountCapped", { count: failedJobs.data.items.length })
        : t("admin:jobs.failedCount", { count: failedJobs.data.items.length });

  return (
    <div className="container mx-auto max-w-7xl space-y-6 px-4 py-8">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">{t("admin:jobs.title")}</h1>
          <p className="text-sm text-muted-foreground">{t("admin:jobs.description")}</p>
        </div>
        <Button
          className="min-h-[44px]"
          variant="outline"
          onClick={() => failedJobs.refetch()}
          disabled={failedJobs.isFetching}
        >
          <RefreshCcw className="size-4" />
          {t("common:actions.refresh")}
        </Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>{t("admin:jobs.failedTitle")}</CardTitle>
          <CardDescription>{failedJobsDescription}</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {failedJobs.isPending ? (
            <JobsSkeleton />
          ) : failedJobs.isError ? (
            <InlineRetry
              className="py-12"
              message={t("admin:jobs.loadFailed")}
              onRetry={() => failedJobs.refetch()}
            />
          ) : failedJobs.data.items.length === 0 ? (
            <div className="flex flex-col items-center gap-3 px-4 py-12 text-center">
              <CheckCircle2 className="size-8 text-muted-foreground" />
              <p className="text-sm font-medium">{t("admin:jobs.noneFailed")}</p>
              <p className="max-w-md text-sm text-muted-foreground">
                {t("admin:jobs.noneFailedDescription")}
              </p>
            </div>
          ) : (
            <ul className="divide-y">
              {failedJobs.data.items.map((job) => (
                <li
                  key={`${job.queue}:${job.id ?? job.timestamp}`}
                  className="grid gap-3 px-4 py-3 md:grid-cols-[minmax(0,1fr)_minmax(0,2fr)_auto]"
                >
                  <div className="min-w-0">
                    <p className="truncate text-sm font-medium">{job.queue}</p>
                    <p className="truncate font-mono text-xs text-muted-foreground">
                      {job.name} · {job.id ?? t("admin:jobs.noJobId")}
                    </p>
                  </div>
                  <p className="min-w-0 break-words text-sm text-destructive">
                    {job.failedReason ?? t("admin:jobs.noFailureReason")}
                  </p>
                  <div className="text-left text-xs text-muted-foreground md:text-right">
                    <p>{t("admin:jobs.attempts", { count: job.attemptsMade })}</p>
                    <time dateTime={new Date(job.finishedOn ?? job.timestamp).toISOString()}>
                      {dateFormatter.format(new Date(job.finishedOn ?? job.timestamp))}
                    </time>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function JobsSkeleton() {
  return (
    <div className="divide-y">
      {Array.from({ length: 5 }).map((_, i) => (
        <div
          key={i}
          className="grid gap-3 px-4 py-3 md:grid-cols-[minmax(0,1fr)_minmax(0,2fr)_auto]"
        >
          <div className="space-y-2">
            <Skeleton className="h-4 w-32" />
            <Skeleton className="h-3 w-48" />
          </div>
          <Skeleton className="h-4 w-full" />
          <Skeleton className="h-8 w-32" />
        </div>
      ))}
    </div>
  );
}
