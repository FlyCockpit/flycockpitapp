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
import { createFileRoute, Link } from "@tanstack/react-router";
import { ArrowLeft, FolderOpen, RefreshCw, WifiOff } from "lucide-react";
import { useTranslation } from "react-i18next";
import { useShallow } from "zustand/react/shallow";
import { InlineRetry } from "@/components/inline-retry";
import { useRemoteInstanceConnection } from "@/hooks/use-remote-instance-connection";
import { useRemoteSessionsStore } from "@/stores/remote-sessions";
import { friendly } from "@/utils/friendly-error";
import { orpc } from "@/utils/orpc";

export const Route = createFileRoute("/$lang/_auth/instances/$instanceId")({
  component: InstanceProjectsPage,
});

function InstanceProjectsPage() {
  const { lang, instanceId } = Route.useParams();
  const { t } = useTranslation("instances");
  const instances = useQuery(orpc.instances.listMine.queryOptions());
  const token = useQuery(orpc.instances.mintClientToken.queryOptions({ input: { instanceId } }));
  useRemoteInstanceConnection(instanceId, token.data);
  const { remote, loadProjects } = useRemoteSessionsStore(
    useShallow((state) => ({
      remote: state.instances[instanceId],
      loadProjects: state.loadProjects,
    })),
  );

  const instance = instances.data?.instances.find((item) => item.id === instanceId);
  const isPending = instances.isPending || token.isPending;
  const isError = instances.isError || token.isError;

  return (
    <div className="container mx-auto max-w-5xl px-4 py-8">
      <div className="mb-6 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="min-w-0">
          <Link
            to="/$lang/instances"
            params={{ lang }}
            className="mb-3 inline-flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground"
          >
            <ArrowLeft className="size-4" />
            {t("remote.backToInstances")}
          </Link>
          <h1 className="truncate text-2xl font-semibold tracking-tight">
            {instance?.displayName ?? t("remote.projectsTitle")}
          </h1>
          <p className="mt-2 text-sm text-muted-foreground">{t("remote.projectsDescription")}</p>
        </div>
        <Button
          type="button"
          variant="outline"
          className="min-h-[44px]"
          onClick={() => void loadProjects(instanceId)}
          disabled={remote?.status !== "connected"}
        >
          <RefreshCw className="size-4" />
          {t("refresh")}
        </Button>
      </div>

      {remote?.status && remote.status !== "connected" ? (
        <div className="mb-4 flex items-center gap-2 rounded-md border bg-muted/40 px-3 py-2 text-sm text-muted-foreground">
          <WifiOff className="size-4" />
          {t("remote.offlineBanner")}
        </div>
      ) : null}

      {isPending ? (
        <ProjectsSkeleton />
      ) : isError ? (
        <InlineRetry
          className="py-12"
          message={friendly(instances.error ?? token.error, t("remote.loadProjectsFailed"))}
          onRetry={() => {
            instances.refetch();
            token.refetch();
          }}
        />
      ) : !remote?.projects.length ? (
        <Card>
          <CardHeader>
            <CardTitle>{t("remote.noProjects")}</CardTitle>
            <CardDescription>{t("remote.noProjectsDescription")}</CardDescription>
          </CardHeader>
        </Card>
      ) : (
        <div className="grid gap-4 sm:grid-cols-2">
          {remote.projects.map((project) => (
            <Link
              key={project.projectId}
              to="/$lang/instances/$instanceId/projects/$projectId"
              params={{ lang, instanceId, projectId: project.projectId }}
              search={{ session: undefined, interrupt: undefined }}
              className="block"
            >
              <Card className="h-full transition-[border-color,box-shadow] hover:border-foreground/30 hover:shadow-sm">
                <CardHeader>
                  <div className="flex items-start gap-3">
                    <FolderOpen className="mt-0.5 size-5 text-muted-foreground" />
                    <div className="min-w-0">
                      <CardTitle className="truncate text-base">{project.displayName}</CardTitle>
                      <CardDescription className="truncate">{project.projectRoot}</CardDescription>
                    </div>
                  </div>
                </CardHeader>
                <CardContent className="grid grid-cols-3 gap-2 text-sm">
                  <Metric label={t("remote.sessions")} value={String(project.sessionCount)} />
                  <Metric label={t("remote.archived")} value={String(project.archivedCount)} />
                  <Metric label={t("remote.attention")} value={String(project.attentionCount)} />
                </CardContent>
              </Card>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="font-medium tabular-nums">{value}</div>
    </div>
  );
}

function ProjectsSkeleton() {
  return (
    <div className="grid gap-4 sm:grid-cols-2">
      {Array.from({ length: 4 }).map((_, index) => (
        <Skeleton key={index} className="h-36 rounded-lg" />
      ))}
    </div>
  );
}
