import { Button } from "@flycockpit/ui/components/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@flycockpit/ui/components/card";
import { Checkbox } from "@flycockpit/ui/components/checkbox";
import { Input } from "@flycockpit/ui/components/input";
import { Skeleton } from "@flycockpit/ui/components/skeleton";
import { useQuery } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import { Database, HardDriveDownload, Trash2 } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useShallow } from "zustand/react/shallow";

import { useRemoteInstanceConnection } from "@/hooks/use-remote-instance-connection";
import { useRemoteSessionsStore } from "@/stores/remote-sessions";
import { orpc } from "@/utils/orpc";

export const Route = createFileRoute("/$lang/_auth/settings/storage")({
  component: StorageSettings,
});

function bytes(value: number) {
  if (value < 1024) return `${value} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let size = value / 1024;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${size.toFixed(size >= 10 || unit === 0 ? 0 : 1)} ${units[unit]}`;
}

function StorageSettings() {
  const { t } = useTranslation("settings");
  const instances = useQuery(orpc.instances.listMine.queryOptions());
  const [instanceId, setInstanceId] = useState("");
  const token = useQuery({
    ...orpc.instances.mintClientToken.queryOptions({ input: { instanceId } }),
    enabled: Boolean(instanceId),
  });
  useRemoteInstanceConnection(instanceId, token.data);
  const [report, setReport] = useState<Awaited<
    ReturnType<ReturnType<typeof useRemoteSessionsStore.getState>["getStorageReport"]>
  > | null>(null);
  const [preview, setPreview] = useState<Awaited<
    ReturnType<ReturnType<typeof useRemoteSessionsStore.getState>["previewStorageCleanup"]>
  > | null>(null);
  const [sessionIds, setSessionIds] = useState("");
  const [includeRenamedOrPinned, setIncludeRenamedOrPinned] = useState(false);
  const [archivedSessionIds, setArchivedSessionIds] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const { remote, getStorageReport, previewStorageCleanup, executeStorageCleanup } =
    useRemoteSessionsStore(
      useShallow((state) => ({
        remote: state.instances[instanceId],
        getStorageReport: state.getStorageReport,
        previewStorageCleanup: state.previewStorageCleanup,
        executeStorageCleanup: state.executeStorageCleanup,
      })),
    );

  const load = async () => {
    if (!instanceId) return;
    setBusy(true);
    setError(null);
    try {
      const nextReport = await getStorageReport(instanceId);
      setReport(nextReport);
      setArchivedSessionIds(
        nextReport.archived_sessions.flatMap((item) => (item.session_id ? [item.session_id] : [])),
      );
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : t("storage.loadError"));
    } finally {
      setBusy(false);
    }
  };
  const createPreview = async (
    target: Parameters<
      ReturnType<typeof useRemoteSessionsStore.getState>["previewStorageCleanup"]
    >[1],
  ) => {
    if (!instanceId) return;
    setBusy(true);
    setError(null);
    try {
      setPreview(await previewStorageCleanup(instanceId, target));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : t("storage.previewError"));
    } finally {
      setBusy(false);
    }
  };
  const execute = async () => {
    if (!instanceId || !preview) return;
    setBusy(true);
    setError(null);
    try {
      const archivedIds =
        preview.preview.target.kind === "archive_sessions_older_than"
          ? preview.preview.items.flatMap((item) => (item.session_id ? [item.session_id] : []))
          : [];
      await executeStorageCleanup(instanceId, preview.preview.preview_id);
      setPreview(null);
      if (archivedIds.length) setArchivedSessionIds(archivedIds);
      await load();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : t("storage.executeError"));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-semibold">{t("storage.title")}</h2>
        <p className="mt-1 text-sm text-muted-foreground">{t("storage.description")}</p>
      </div>
      <Card>
        <CardHeader>
          <CardTitle>{t("storage.chooseInstance")}</CardTitle>
          <CardDescription>{t("storage.instanceDescription")}</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-2">
          {instances.isPending ? <Skeleton className="h-10 w-40" /> : null}
          {instances.data?.instances.map((instance) => (
            <Button
              key={instance.id}
              type="button"
              variant={instanceId === instance.id ? "default" : "outline"}
              onClick={() => {
                setInstanceId(instance.id);
                setReport(null);
                setPreview(null);
                setArchivedSessionIds([]);
              }}
            >
              {instance.displayName}
            </Button>
          ))}
        </CardContent>
      </Card>
      {instanceId ? (
        <>
          <div className="flex items-center gap-3">
            <Button
              type="button"
              onClick={() => void load()}
              disabled={busy || remote?.status !== "connected"}
            >
              <Database className="size-4" />
              {t("storage.refresh")}
            </Button>
            {remote?.status !== "connected" ? (
              <p className="text-sm text-muted-foreground">{t("storage.waitingForInstance")}</p>
            ) : null}
          </div>
          {report ? (
            <>
              <Card>
                <CardHeader>
                  <CardTitle>{t("storage.total", { size: bytes(report.total_bytes) })}</CardTitle>
                  <CardDescription>{t("storage.breakdownDescription")}</CardDescription>
                </CardHeader>
                <CardContent className="space-y-2 text-sm">
                  {report.categories.map((category) => (
                    <div key={category.category} className="flex justify-between gap-4">
                      <span>{t(`storage.categories.${category.category}`)}</span>
                      <span className="text-right tabular-nums">
                        {bytes(category.total_bytes)}
                        <span className="ml-2 text-muted-foreground">
                          {t("storage.reclaimable", { size: bytes(category.reclaimable_bytes) })}
                        </span>
                      </span>
                    </div>
                  ))}
                </CardContent>
              </Card>
              <Card>
                <CardHeader>
                  <CardTitle>{t("storage.quickActions")}</CardTitle>
                  <CardDescription>{t("storage.previewRequired")}</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="space-y-2">
                    <Button
                      type="button"
                      variant="outline"
                      disabled={busy}
                      onClick={() => {
                        setArchivedSessionIds([]);
                        void createPreview({
                          kind: "archive_sessions_older_than",
                          data: {
                            age_days: 30,
                            include_renamed_or_pinned: includeRenamedOrPinned,
                          },
                        });
                      }}
                    >
                      <HardDriveDownload className="size-4" />
                      {t("storage.archiveOlderThan30")}
                    </Button>
                    <label className="flex items-center gap-2 text-sm text-muted-foreground">
                      <Checkbox
                        checked={includeRenamedOrPinned}
                        onCheckedChange={(checked) => setIncludeRenamedOrPinned(checked === true)}
                      />
                      {t("storage.includeRenamedOrPinned")}
                    </label>
                  </div>
                  {archivedSessionIds.length ? (
                    <div className="space-y-2 rounded-md border border-destructive/30 p-3">
                      <p className="text-sm">{t("storage.archivedReadyForDeletion")}</p>
                      <Button
                        type="button"
                        variant="destructive"
                        disabled={busy}
                        onClick={() =>
                          void createPreview({
                            kind: "permanently_delete_sessions",
                            data: { session_ids: archivedSessionIds },
                          })
                        }
                      >
                        {t("storage.previewArchivedDelete")}
                      </Button>
                    </div>
                  ) : null}
                  {report.archived_sessions.length ? (
                    <div className="space-y-3 rounded-md border p-3">
                      <div>
                        <p className="text-sm font-medium">{t("storage.archivedSessions")}</p>
                        <p className="text-sm text-muted-foreground">
                          {t("storage.archivedSessionsDescription")}
                        </p>
                      </div>
                      <ul className="space-y-1 text-sm">
                        {report.archived_sessions.map((item) => (
                          <li
                            key={item.session_id ?? item.label}
                            className="flex justify-between gap-4"
                          >
                            <span className="truncate">{item.label}</span>
                            <span className="tabular-nums">{bytes(item.bytes)}</span>
                          </li>
                        ))}
                      </ul>
                      <Button
                        type="button"
                        variant="destructive"
                        disabled={busy}
                        onClick={() =>
                          void createPreview({
                            kind: "permanently_delete_sessions",
                            data: {
                              session_ids: report.archived_sessions.flatMap((item) =>
                                item.session_id ? [item.session_id] : [],
                              ),
                            },
                          })
                        }
                      >
                        {t("storage.previewArchivedDelete")}
                      </Button>
                    </div>
                  ) : null}
                  {report.orphaned_workspace_storage.length ? (
                    <Button
                      type="button"
                      variant="outline"
                      disabled={busy}
                      onClick={() =>
                        void createPreview({
                          kind: "remove_orphaned_workspace_storage",
                          data: {
                            project_ids: report.orphaned_workspace_storage.map(
                              (item) => item.label,
                            ),
                          },
                        })
                      }
                    >
                      <Trash2 className="size-4" />
                      {t("storage.removeOrphans")}
                    </Button>
                  ) : null}
                  <div className="space-y-2 border-t pt-4">
                    <label htmlFor="session-ids" className="text-sm font-medium">
                      {t("storage.permanentDelete")}
                    </label>
                    <Input
                      id="session-ids"
                      value={sessionIds}
                      onChange={(event) => setSessionIds(event.target.value)}
                      placeholder={t("storage.sessionIdsPlaceholder")}
                    />
                    <Button
                      type="button"
                      variant="destructive"
                      disabled={busy || !sessionIds.trim()}
                      onClick={() =>
                        void createPreview({
                          kind: "permanently_delete_sessions",
                          data: { session_ids: sessionIds.split(/[\s,]+/).filter(Boolean) },
                        })
                      }
                    >
                      {t("storage.previewDelete")}
                    </Button>
                  </div>
                </CardContent>
              </Card>
            </>
          ) : null}
        </>
      ) : null}
      {preview ? (
        <Card>
          <CardHeader>
            <CardTitle>{t("storage.previewTitle")}</CardTitle>
            <CardDescription>
              {t("storage.previewDescription", { size: bytes(preview.preview.bytes_to_free) })}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <ul className="space-y-1 text-sm">
              {preview.preview.items.map((item) => (
                <li key={item.label} className="flex justify-between gap-4">
                  <span className="truncate">{item.label}</span>
                  <span>{bytes(item.bytes)}</span>
                </li>
              ))}
            </ul>
            <Button
              type="button"
              variant="destructive"
              disabled={busy}
              onClick={() => void execute()}
            >
              {t("storage.confirm")}
            </Button>
          </CardContent>
        </Card>
      ) : null}
      {error ? <p className="text-sm text-destructive">{error}</p> : null}
    </div>
  );
}
