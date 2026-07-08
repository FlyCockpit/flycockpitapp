import { Button } from "@flycockpit/ui/components/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@flycockpit/ui/components/card";
import { toast } from "@flycockpit/ui/components/sileo";
import { Skeleton } from "@flycockpit/ui/components/skeleton";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute, Link } from "@tanstack/react-router";
import { AlertTriangle, ArrowLeft, FileWarning, HardDrive, RefreshCw } from "lucide-react";
import { useState } from "react";
import { Trans, useTranslation } from "react-i18next";

import { InlineRetry } from "@/components/inline-retry";
import { useHaptics } from "@/hooks/use-haptics";
import { orpc } from "@/utils/orpc";

export const Route = createFileRoute("/$lang/admin/assets/cleanup")({
  component: AdminAssetsCleanup,
});

type CleanupCandidate = {
  kind: "pending-row" | "orphan-object" | "incomplete-multipart";
  id: string;
  size: number;
  ageReference: string | Date | null;
};

type CleanupSummary = {
  pendingRows: { count: number; bytes: number; sample: CleanupCandidate[] };
  orphanObjects: { count: number; bytes: number; sample: CleanupCandidate[] };
  incompleteMultipart: { count: number; sample: CleanupCandidate[] };
};

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

function formatAge(value: string | Date | null, locale: string): string {
  if (!value) return "—";
  const d = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(d.getTime())) return "—";
  const diff = Date.now() - d.getTime();
  const formatter = new Intl.RelativeTimeFormat(locale, { numeric: "auto" });
  const hours = Math.floor(diff / 3600_000);
  if (hours >= 48) return formatter.format(-Math.floor(hours / 24), "day");
  if (hours >= 1) return formatter.format(-hours, "hour");
  const minutes = Math.floor(diff / 60_000);
  return formatter.format(-minutes, "minute");
}

function AdminAssetsCleanup() {
  const { lang } = Route.useParams();
  const queryClient = useQueryClient();
  const { trigger } = useHaptics();
  const [activeJobId, setActiveJobId] = useState<string | null>(null);
  const { t } = useTranslation(["admin", "common"]);

  const dryRun = useQuery({
    ...orpc.assets.cleanupDryRun.queryOptions(),
    // The dry-run iterates the whole asset prefix in S3, which can be slow
    // on big buckets. Don't auto-refetch on focus — admin clicks "Refresh"
    // when they want fresh numbers.
    refetchOnWindowFocus: false,
    staleTime: Infinity,
  });

  const enqueue = useMutation({
    ...orpc.assets.cleanupEnqueue.mutationOptions({
      onSuccess: (data) => {
        setActiveJobId(data.jobId);
        trigger("success");
        toast.success(t("admin:assets.cleanupPage.enqueued"));
      },
      onError: () => {
        trigger("error");
      },
    }),
    meta: { errorFallbackKey: "admin:assets.cleanupPage.enqueueFailed" },
  });

  const jobStatus = useQuery({
    ...orpc.queue.getJob.queryOptions({
      input: activeJobId ? { jobId: activeJobId, queue: "cleanup-assets" } : { jobId: "" },
    }),
    enabled: !!activeJobId,
    refetchInterval: (q) => {
      const state = q.state.data?.state;
      return state === "completed" || state === "failed" ? false : 2000;
    },
  });

  const summary = (dryRun.data ?? null) as CleanupSummary | null;
  const totalCandidates =
    (summary?.pendingRows.count ?? 0) +
    (summary?.orphanObjects.count ?? 0) +
    (summary?.incompleteMultipart.count ?? 0);

  const jobIsRunning =
    !!activeJobId &&
    jobStatus.data &&
    jobStatus.data.state !== "completed" &&
    jobStatus.data.state !== "failed";

  return (
    <div className="container mx-auto max-w-4xl px-4 py-8 space-y-6">
      <header className="space-y-2">
        <Link
          to="/$lang/admin/assets"
          params={{ lang }}
          className="inline-flex min-h-[44px] items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
        >
          <ArrowLeft className="size-4" />
          {t("admin:assets.cleanupPage.back")}
        </Link>
        <h1 className="text-2xl font-semibold tracking-tight">
          {t("admin:assets.cleanupPage.title")}
        </h1>
        <p className="text-sm text-muted-foreground">
          <Trans i18nKey="assets.cleanupPage.description" t={t} components={[<code key="0" />]} />
        </p>
        <p className="text-xs text-muted-foreground">
          <Trans
            i18nKey="assets.cleanupPage.subDescription"
            t={t}
            components={[<code key="0" />, <strong key="1" />]}
          />
        </p>
      </header>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-4">
          <div>
            <CardTitle>{t("admin:assets.cleanupPage.dryRunTitle")}</CardTitle>
            <CardDescription>
              <Trans
                i18nKey="assets.cleanupPage.dryRunDescription"
                t={t}
                components={[<strong key="0" />]}
              />
            </CardDescription>
          </div>
          <Button
            variant="outline"
            size="sm"
            className="min-h-[44px]"
            onClick={() => {
              trigger("light");
              void queryClient.invalidateQueries({
                queryKey: orpc.assets.cleanupDryRun.key(),
              });
            }}
            disabled={dryRun.isFetching}
          >
            <RefreshCw className={`size-4 ${dryRun.isFetching ? "animate-spin" : ""}`} />
            {t("admin:assets.cleanupPage.refresh")}
          </Button>
        </CardHeader>
        <CardContent className="space-y-6">
          {dryRun.isPending ? (
            <div className="space-y-2">
              <Skeleton className="h-20 w-full" />
              <Skeleton className="h-20 w-full" />
              <Skeleton className="h-20 w-full" />
            </div>
          ) : dryRun.isError ? (
            <InlineRetry
              variant="destructive"
              onRetry={() => dryRun.refetch()}
              message={dryRun.error.message}
            />
          ) : summary ? (
            <div className="space-y-4">
              <CategoryCard
                icon={FileWarning}
                title={t("admin:assets.cleanupPage.orphanPendingTitle")}
                description={t("admin:assets.cleanupPage.orphanPendingDescription")}
                count={summary.pendingRows.count}
                bytes={summary.pendingRows.bytes}
                sample={summary.pendingRows.sample}
              />
              <CategoryCard
                icon={HardDrive}
                title={t("admin:assets.cleanupPage.unrefObjectsTitle")}
                description={t("admin:assets.cleanupPage.unrefObjectsDescription")}
                count={summary.orphanObjects.count}
                bytes={summary.orphanObjects.bytes}
                sample={summary.orphanObjects.sample}
              />
              <CategoryCard
                icon={AlertTriangle}
                title={t("admin:assets.cleanupPage.incompleteMultipartTitle")}
                description={t("admin:assets.cleanupPage.incompleteMultipartDescription")}
                count={summary.incompleteMultipart.count}
                bytes={null}
                sample={summary.incompleteMultipart.sample}
              />
            </div>
          ) : null}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>{t("admin:assets.cleanupPage.runTitle")}</CardTitle>
          <CardDescription>
            <Trans
              i18nKey="assets.cleanupPage.runDescription"
              t={t}
              components={[<code key="0" />]}
            />
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <Button
            variant="destructive"
            className="min-h-[44px]"
            disabled={enqueue.isPending || jobIsRunning || totalCandidates === 0}
            onClick={() => {
              trigger("warning");
              enqueue.mutate({});
            }}
          >
            {jobIsRunning
              ? t("admin:assets.cleanupPage.running")
              : totalCandidates === 0
                ? t("admin:assets.cleanupPage.nothingToClean")
                : t("admin:assets.cleanupPage.runWithCount", { count: totalCandidates })}
          </Button>
          {activeJobId ? <JobStatus job={jobStatus.data} /> : null}
        </CardContent>
      </Card>
    </div>
  );
}

function CategoryCard({
  icon: Icon,
  title,
  description,
  count,
  bytes,
  sample,
}: {
  icon: React.ComponentType<{ className?: string }>;
  title: string;
  description: string;
  count: number;
  bytes: number | null;
  sample: CleanupCandidate[];
}) {
  const { i18n, t } = useTranslation("admin");
  return (
    <div className="rounded-md border bg-muted/30 p-4">
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-start gap-3 min-w-0">
          <Icon className="size-5 shrink-0 text-muted-foreground" />
          <div className="min-w-0">
            <h3 className="font-medium">{title}</h3>
            <p className="text-sm text-muted-foreground">{description}</p>
          </div>
        </div>
        <div className="text-right tabular-nums shrink-0">
          <p className="text-2xl font-semibold">{count}</p>
          {bytes !== null && <p className="text-xs text-muted-foreground">{formatBytes(bytes)}</p>}
        </div>
      </div>
      {sample.length > 0 ? (
        <details className="mt-3">
          <summary className="cursor-pointer text-xs text-muted-foreground hover:text-foreground">
            {t("assets.cleanupPage.showFirstOf", { shown: sample.length, total: count })}
          </summary>
          <ul className="mt-2 space-y-1 text-xs">
            {sample.map((item) => (
              <li
                key={item.id}
                className="flex items-center gap-2 rounded bg-background px-2 py-1 font-mono"
              >
                <span className="truncate flex-1">{item.id}</span>
                {item.size > 0 && (
                  <span className="text-muted-foreground shrink-0">{formatBytes(item.size)}</span>
                )}
                <span className="text-muted-foreground shrink-0">
                  {formatAge(item.ageReference, i18n.language)}
                </span>
              </li>
            ))}
          </ul>
        </details>
      ) : null}
    </div>
  );
}

function JobStatus({
  job,
}: {
  job:
    | {
        id: string | undefined;
        state: string;
        returnValue: unknown;
        failedReason: string | null;
      }
    | null
    | undefined;
}) {
  const { t } = useTranslation("admin");
  if (!job)
    return <p className="text-xs text-muted-foreground">{t("assets.cleanupPage.jobWaiting")}</p>;
  if (job.state === "completed") {
    const result = job.returnValue as Record<string, number | string> | null;
    return (
      <div className="rounded-md border bg-muted/30 p-3 text-sm">
        <p className="font-medium">{t("assets.cleanupPage.jobCompleteTitle")}</p>
        {result ? (
          <dl className="mt-2 grid grid-cols-2 gap-x-3 gap-y-1 text-xs tabular-nums">
            <Stat
              label={t("assets.cleanupPage.stat.pendingRowsDeleted")}
              value={result.pendingRowsDeleted}
            />
            <Stat
              label={t("assets.cleanupPage.stat.pendingStorageObjectsDeleted")}
              value={result.pendingStorageObjectsDeleted}
            />
            <Stat
              label={t("assets.cleanupPage.stat.orphanObjectsDeleted")}
              value={result.orphanObjectsDeleted}
            />
            <Stat
              label={t("assets.cleanupPage.stat.multipartAborted")}
              value={result.multipartAborted}
            />
            <Stat
              label={t("assets.cleanupPage.stat.bytesFreed")}
              value={typeof result.bytesFreed === "number" ? formatBytes(result.bytesFreed) : "—"}
            />
            <Stat
              label={t("assets.cleanupPage.stat.orphanObjectsFailed")}
              value={result.orphanObjectsFailed}
            />
          </dl>
        ) : null}
      </div>
    );
  }
  if (job.state === "failed") {
    return (
      <div className="rounded-md border border-destructive/30 bg-destructive/5 p-3 text-sm">
        <p className="font-medium text-destructive">{t("assets.cleanupPage.jobFailedTitle")}</p>
        {job.failedReason ? (
          <p className="mt-1 text-xs text-destructive">{job.failedReason}</p>
        ) : null}
      </div>
    );
  }
  return (
    <p className="text-xs text-muted-foreground">
      {t("assets.cleanupPage.jobState", { state: job.state })}
    </p>
  );
}

function Stat({ label, value }: { label: string; value: number | string | undefined }) {
  return (
    <>
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="text-right font-medium">{value ?? "—"}</dd>
    </>
  );
}
