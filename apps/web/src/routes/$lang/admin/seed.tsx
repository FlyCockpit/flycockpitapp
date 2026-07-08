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
import { useMutation, useQuery } from "@tanstack/react-query";
import { createFileRoute, Link } from "@tanstack/react-router";
import { AlertTriangle, ArrowLeft, Database } from "lucide-react";
import { useState } from "react";
import { Trans, useTranslation } from "react-i18next";

import { ConfirmDeleteDialog } from "@/components/confirm-delete-dialog";
import { InlineRetry } from "@/components/inline-retry";
import { useHaptics } from "@/hooks/use-haptics";
import { orpc } from "@/utils/orpc";

export const Route = createFileRoute("/$lang/admin/seed")({
  component: AdminSeed,
});

type SeedJobReturn = { summary?: string[]; durationMs?: number } | null;

function AdminSeed() {
  const { lang } = Route.useParams();
  const { trigger } = useHaptics();
  const { t } = useTranslation(["admin", "common"]);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [activeJobId, setActiveJobId] = useState<string | null>(null);

  const info = useQuery({
    ...orpc.seed.info.queryOptions(),
    refetchOnWindowFocus: false,
    staleTime: Infinity,
  });

  const run = useMutation({
    ...orpc.seed.run.mutationOptions({
      onSuccess: (data) => {
        if (data.jobId) setActiveJobId(data.jobId);
        trigger("success");
        toast.success(t("admin:seedPage.enqueued"));
      },
      onError: () => {
        trigger("error");
      },
    }),
    meta: { errorFallbackKey: "admin:seedPage.enqueueFailed" },
  });

  const jobStatus = useQuery({
    ...orpc.queue.getJob.queryOptions({
      input: activeJobId ? { jobId: activeJobId, queue: "seed" } : { jobId: "" },
    }),
    enabled: !!activeJobId,
    refetchInterval: (q) => {
      const state = q.state.data?.state;
      return state === "completed" || state === "failed" ? false : 2000;
    },
  });

  const jobIsRunning =
    !!activeJobId &&
    jobStatus.data &&
    jobStatus.data.state !== "completed" &&
    jobStatus.data.state !== "failed";

  return (
    <div className="container mx-auto max-w-3xl px-4 py-8 space-y-6">
      <header className="space-y-2">
        <Link
          to="/$lang/admin"
          params={{ lang }}
          className="inline-flex min-h-[44px] items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
        >
          <ArrowLeft className="size-4" />
          {t("admin:seedPage.back")}
        </Link>
        <h1 className="flex items-center gap-2 text-2xl font-semibold tracking-tight">
          <Database className="size-6" aria-hidden />
          {t("admin:seedPage.title")}
        </h1>
        <p className="text-sm text-muted-foreground">
          <Trans i18nKey="seedPage.description" t={t} components={[<code key="0" />]} />
        </p>
        <p className="text-xs text-muted-foreground">
          <Trans i18nKey="seedPage.workerNote" t={t} components={[<code key="0" />]} />
        </p>
      </header>

      {info.isPending ? (
        <Skeleton className="h-40 w-full" />
      ) : info.isError ? (
        <InlineRetry
          variant="destructive"
          onRetry={() => info.refetch()}
          message={t("admin:seedPage.loadInfoFailed")}
        />
      ) : (
        <>
          {info.data.isProduction && (
            <Card className="border-destructive/40 bg-destructive/5">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-destructive">
                  <AlertTriangle className="size-5" aria-hidden />
                  {t("admin:seedPage.prodWarningTitle")}
                </CardTitle>
                <CardDescription className="text-destructive/90">
                  {t("admin:seedPage.prodWarningBody")}
                </CardDescription>
              </CardHeader>
            </Card>
          )}

          <Card>
            <CardHeader>
              <CardTitle>{t("admin:seedPage.runTitle")}</CardTitle>
              <CardDescription>{t("admin:seedPage.emptyStubNote")}</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <Button
                variant="destructive"
                className="min-h-[44px]"
                disabled={run.isPending || !!jobIsRunning}
                onClick={() => {
                  trigger("warning");
                  setConfirmOpen(true);
                }}
              >
                {jobIsRunning ? t("admin:seedPage.running") : t("admin:seedPage.runButton")}
              </Button>
              {activeJobId ? <JobStatus job={jobStatus.data} /> : null}
            </CardContent>
          </Card>

          <ConfirmDeleteDialog
            open={confirmOpen}
            onOpenChange={setConfirmOpen}
            title={t("admin:seedPage.confirmTitle")}
            description={
              info.data.isProduction
                ? t("admin:seedPage.confirmDescriptionProd")
                : t("admin:seedPage.confirmDescription")
            }
            confirmToken={info.data.requiredConfirmPhrase}
            typePrompt={t("admin:seedPage.typePrompt")}
            copyAriaLabel={t("admin:seedPage.copyAria")}
            inputMode="text"
            confirmLabel={t("admin:seedPage.confirmCta")}
            pendingLabel={t("admin:seedPage.confirmPending")}
            isPending={run.isPending}
            onConfirm={(confirmValue) => {
              run.mutate({ confirm: confirmValue }, { onSuccess: () => setConfirmOpen(false) });
            }}
          />
        </>
      )}
    </div>
  );
}

function JobStatus({
  job,
}: {
  job:
    | { id: string | undefined; state: string; returnValue: unknown; failedReason: string | null }
    | null
    | undefined;
}) {
  const { t } = useTranslation("admin");
  if (!job) return <p className="text-xs text-muted-foreground">{t("seedPage.jobWaiting")}</p>;

  if (job.state === "completed") {
    const result = job.returnValue as SeedJobReturn;
    const summary = result?.summary ?? [];
    return (
      <div className="rounded-md border bg-muted/30 p-3 text-sm">
        <p className="font-medium">{t("seedPage.jobCompleteTitle")}</p>
        {typeof result?.durationMs === "number" && (
          <p className="mt-1 text-xs text-muted-foreground tabular-nums">
            {t("seedPage.jobDuration", { ms: result.durationMs })}
          </p>
        )}
        {summary.length === 0 ? (
          <p className="mt-2 text-xs text-muted-foreground">{t("seedPage.jobEmpty")}</p>
        ) : (
          <ul className="mt-2 space-y-1 text-xs">
            {summary.map((line, i) => (
              <li
                key={`${i}-${line}`}
                className="rounded bg-background px-2 py-1 font-mono break-all"
              >
                {line}
              </li>
            ))}
          </ul>
        )}
      </div>
    );
  }

  if (job.state === "failed") {
    return (
      <div className="rounded-md border border-destructive/30 bg-destructive/5 p-3 text-sm">
        <p className="font-medium text-destructive">{t("seedPage.jobFailedTitle")}</p>
        {job.failedReason ? (
          <p className="mt-1 text-xs text-destructive break-all">{job.failedReason}</p>
        ) : null}
      </div>
    );
  }

  return (
    <p className="text-xs text-muted-foreground">{t("seedPage.jobState", { state: job.state })}</p>
  );
}
