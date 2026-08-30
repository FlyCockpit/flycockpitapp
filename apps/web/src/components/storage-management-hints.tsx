import { Button } from "@flycockpit/ui/components/button";
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { useRemoteInstanceConnection } from "@/hooks/use-remote-instance-connection";
import { useRemoteSessionsStore } from "@/stores/remote-sessions";
import { orpc } from "@/utils/orpc";

export function StorageManagementHints({ lang }: { lang: string }) {
  const instances = useQuery(orpc.instances.listMine.queryOptions());
  return (
    <div className="container mx-auto max-w-4xl space-y-2 px-4 pt-4">
      {instances.data?.instances.map((instance) => (
        <InstanceStorageManagementHint key={instance.id} instanceId={instance.id} lang={lang} />
      ))}
    </div>
  );
}

function InstanceStorageManagementHint({ instanceId, lang }: { instanceId: string; lang: string }) {
  const { t } = useTranslation("settings");
  const [dismissed, setDismissed] = useState(false);
  const token = useQuery({
    ...orpc.instances.mintClientToken.queryOptions({ input: { instanceId } }),
    enabled: Boolean(instanceId),
  });
  useRemoteInstanceConnection(instanceId, token.data);
  const remote = useRemoteSessionsStore((state) => state.instances[instanceId]);
  const getStorageReport = useRemoteSessionsStore((state) => state.getStorageReport);
  const dismissStorageManagementHint = useRemoteSessionsStore(
    (state) => state.dismissStorageManagementHint,
  );
  const report = useQuery({
    queryKey: ["storage-management-hint", instanceId],
    queryFn: () => getStorageReport(instanceId),
    enabled: remote?.status === "connected" && !dismissed,
    staleTime: 5 * 60 * 1000,
  });

  if (dismissed || !report.data?.show_management_hint) return null;
  return (
    <div className="flex items-center justify-between gap-3 rounded-md border bg-muted/40 px-3 py-2 text-sm">
      <Link to="/$lang/settings/storage" params={{ lang }} className="font-medium hover:underline">
        {t("storage.hint", { size: formatBytes(report.data.total_bytes) })}
      </Link>
      <Button
        type="button"
        size="sm"
        variant="ghost"
        onClick={() =>
          void dismissStorageManagementHint(
            instanceId,
            report.data.storage_management_hint_version,
          ).then(() => setDismissed(true))
        }
      >
        {t("storage.dismiss")}
      </Button>
    </div>
  );
}

function formatBytes(value: number) {
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
