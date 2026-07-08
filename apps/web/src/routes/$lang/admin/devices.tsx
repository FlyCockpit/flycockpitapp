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
import { createFileRoute } from "@tanstack/react-router";
import { Smartphone, Trash } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { ConfirmDeleteDialog } from "@/components/confirm-delete-dialog";
import { InlineRetry } from "@/components/inline-retry";
import { friendly } from "@/utils/friendly-error";
import { orpc } from "@/utils/orpc";

export const Route = createFileRoute("/$lang/admin/devices")({
  component: AdminDevices,
});

function AdminDevices() {
  const queryClient = useQueryClient();
  const [revokeId, setRevokeId] = useState<string | null>(null);
  const { t } = useTranslation(["admin", "common"]);

  const list = useQuery(orpc.devices.list.queryOptions({ input: { limit: 50 } }));
  const revoke = useMutation({
    ...orpc.devices.revoke.mutationOptions({
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: orpc.devices.key() });
        toast.success(t("admin:devices.markedDenied"));
        setRevokeId(null);
      },
    }),
    meta: { errorFallbackKey: "admin:devices.denyFailed" },
  });

  const target = list.data?.find((d) => d.id === revokeId) ?? null;
  const revokeToken = target?.userCode ?? "";

  return (
    <div className="container mx-auto max-w-3xl px-4 py-8 space-y-6">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">{t("admin:devices.title")}</h1>
        <p className="text-sm text-muted-foreground">{t("admin:devices.description")}</p>
      </header>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Smartphone className="size-4" /> {t("admin:devices.recentTitle")}
          </CardTitle>
          <CardDescription>{t("admin:devices.recentDescription")}</CardDescription>
        </CardHeader>
        <CardContent>
          {list.isPending ? (
            <div className="space-y-2">
              <Skeleton className="h-12 w-full" />
              <Skeleton className="h-12 w-full" />
            </div>
          ) : list.isError ? (
            <InlineRetry
              variant="destructive"
              onRetry={() => list.refetch()}
              message={friendly(list.error, t("admin:devices.loadFailed"))}
            />
          ) : (list.data ?? []).length === 0 ? (
            <div className="rounded-md border border-dashed py-10 text-center">
              <p className="text-sm font-medium">{t("admin:devices.noCodes")}</p>
              <p className="mt-1 text-sm text-muted-foreground">{t("admin:devices.noCodesHint")}</p>
            </div>
          ) : (
            <ul className="divide-y">
              {(list.data ?? []).map((device) => (
                <li key={device.id} className="flex items-center justify-between gap-4 py-3">
                  <div className="min-w-0 space-y-0.5">
                    <p className="font-medium">
                      <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">
                        {device.userCode}
                      </code>
                      <StatusBadge status={device.status} />
                    </p>
                    <p className="text-xs text-muted-foreground">
                      {device.clientId
                        ? t("admin:devices.clientPrefix", { clientId: device.clientId })
                        : ""}
                      {t("admin:devices.createdExpires", {
                        created: formatDate(device.createdAt),
                        expires: formatDate(device.expiresAt),
                      })}
                    </p>
                  </div>
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    aria-label={t("admin:devices.denyAriaLabel", { code: device.userCode })}
                    onClick={() => setRevokeId(device.id)}
                    className="min-h-[44px]"
                    disabled={device.status === "denied"}
                  >
                    <Trash className="size-4" />
                  </Button>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>

      <ConfirmDeleteDialog
        open={!!revokeId}
        onOpenChange={(open) => {
          if (!open) setRevokeId(null);
        }}
        title={t("admin:devices.denyTitle")}
        description={
          target
            ? t("admin:devices.denyDescriptionNamed", { code: target.userCode })
            : t("admin:devices.denyDescriptionUnnamed")
        }
        confirmToken={revokeToken}
        typePrompt={t("admin:devices.typeUserCodeToConfirm")}
        copyAriaLabel={t("admin:devices.copyUserCodeAriaLabel")}
        confirmLabel={t("admin:devices.markDenied")}
        pendingLabel={t("admin:devices.savingMark")}
        isPending={revoke.isPending}
        onConfirm={() => revokeId && revoke.mutate({ id: revokeId })}
      />
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  const { t } = useTranslation("admin");
  const tone =
    status === "approved"
      ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400"
      : status === "denied"
        ? "border-destructive/30 bg-destructive/10 text-destructive"
        : "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300";
  const label =
    status === "approved"
      ? t("devices.statusApproved")
      : status === "denied"
        ? t("devices.statusDenied")
        : t("devices.statusPending");
  return (
    <span className={`ml-2 rounded-full border px-2 py-0.5 text-[10px] font-medium ${tone}`}>
      {label}
    </span>
  );
}

function formatDate(value: Date | string): string {
  const d = typeof value === "string" ? new Date(value) : value;
  return d.toLocaleString();
}
