import { Button } from "@flycockpit/ui/components/button";
import { useQuery } from "@tanstack/react-query";
import { createFileRoute, Link, Outlet } from "@tanstack/react-router";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { useRemoteInstanceConnection } from "@/hooks/use-remote-instance-connection";
import { settingsNavItems } from "@/lib/nav-items";
import { useRemoteSessionsStore } from "@/stores/remote-sessions";
import { orpc } from "@/utils/orpc";

export const Route = createFileRoute("/$lang/_auth/settings")({
  component: SettingsLayout,
});

type SettingsRoute =
  | "/$lang/settings"
  | "/$lang/settings/security"
  | "/$lang/settings/privacy"
  | "/$lang/settings/storage";

function SettingsLayout() {
  const { lang } = Route.useParams();
  const { t } = useTranslation(["settings", "consent"]);
  // Rendered from the shared, ordered `settingsNavItems` so the visual tab order
  // and the slide-direction order in `getNavDirection` can never drift.
  const navItems = settingsNavItems.map((item) => ({
    to: `/$lang${item.path}` as SettingsRoute,
    label: t(item.labelKey),
    icon: item.icon,
    exact: item.exact,
  }));

  return (
    <div className="container mx-auto max-w-4xl px-4 py-8">
      <h1 className="text-2xl font-semibold mb-6">{t("title")}</h1>
      <StorageManagementHints lang={lang} />
      <div className="flex flex-col gap-6 md:flex-row md:gap-8">
        <nav
          className="w-full min-w-0 md:w-48 flex-shrink-0"
          style={{ viewTransitionName: "settings-subnav" }}
        >
          <div className="-mx-4 flex flex-row gap-1 overflow-x-auto px-4 no-scrollbar md:mx-0 md:flex-col md:overflow-x-visible md:px-0">
            {navItems.map((item) => (
              <Link
                key={item.to}
                to={item.to}
                params={{ lang }}
                activeOptions={{ exact: item.exact }}
                className="flex shrink-0 items-center gap-2 rounded-md px-3 py-2 text-sm text-muted-foreground hover:bg-accent hover:text-accent-foreground transition-colors md:shrink"
                activeProps={{
                  className:
                    "flex shrink-0 items-center gap-2 rounded-md px-3 py-2 text-sm bg-accent text-accent-foreground transition-colors md:shrink",
                }}
              >
                <item.icon className="size-4" />
                {item.label}
              </Link>
            ))}
          </div>
        </nav>
        <div className="flex-1 min-w-0">
          <Outlet />
        </div>
      </div>
    </div>
  );
}

function StorageManagementHints({ lang }: { lang: string }) {
  const instances = useQuery(orpc.instances.listMine.queryOptions());
  return (
    <div className="mb-6 space-y-2">
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
