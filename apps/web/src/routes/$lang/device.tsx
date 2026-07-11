import { env } from "@flycockpit/env/web";
import { Button } from "@flycockpit/ui/components/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@flycockpit/ui/components/card";
import { toast } from "@flycockpit/ui/components/sileo";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute, Link, redirect } from "@tanstack/react-router";
import { ShieldCheck, ShieldX } from "lucide-react";
import { useState } from "react";
import { Trans, useTranslation } from "react-i18next";
import { authClient } from "@/lib/auth-client";
import { decideDeviceRouteAccess } from "@/lib/route-session-access";
import { getRouteSession } from "@/server/auth-session";
import { friendly } from "@/utils/friendly-error";
import { orpc } from "@/utils/orpc";

// OAuth 2.0 Device Authorization Grant verification page (RFC 8628 §3.3).
// Device clients link a signed-in user here with `?user_code=…`. cockpit-cli
// codes are user-owned; admin/MCP codes remain admin-gated by the server-side
// approve/deny middleware. Unauthenticated visitors bounce through /login.
export const Route = createFileRoute("/$lang/device")({
  validateSearch: (search: Record<string, unknown>) => {
    const userCode = typeof search.user_code === "string" ? search.user_code : undefined;
    return { user_code: userCode };
  },
  beforeLoad: async ({ location, params }) => {
    const decision = decideDeviceRouteAccess(await getRouteSession());
    if (decision.kind === "error") throw new Error("Could not verify session");
    if (decision.kind === "redirect-to-login") {
      throw redirect({
        to: "/$lang/login",
        params: { lang: params.lang },
        search: { redirectTo: location.href },
      });
    }
    if (decision.kind === "redirect-to-dashboard") {
      throw redirect({ to: "/$lang/dashboard", params: { lang: params.lang } });
    }
    return { session: decision.session };
  },
  component: DevicePage,
});

type Decision = "approved" | "denied" | null;

function DevicePage() {
  const { lang } = Route.useParams();
  const search = Route.useSearch();
  const userCode = search.user_code ?? "";
  const [decision, setDecision] = useState<Decision>(null);
  const queryClient = useQueryClient();
  const { t } = useTranslation("auth");
  const deviceCode = useQuery({
    ...orpc.instances.lookupDeviceCode.queryOptions({ input: { userCode } }),
    enabled: Boolean(userCode),
  });
  const isCliDevice = deviceCode.data?.clientId === "cockpit-cli";

  const approveMutation = useMutation({
    mutationFn: async () => {
      await claimDeviceCode(userCode);
      const result = await authClient.device.approve({ userCode });
      if (result.error) {
        throw new Error(result.error.error_description ?? "Failed to approve");
      }
      return result.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: orpc.devices.key() });
      setDecision("approved");
      toast.success(t("device.approveSuccess"));
    },
    onError: (err) => {
      console.error("[device.approve]", err);
      toast.error(friendly(err, t("device.approveError")));
    },
    meta: { skipGlobalErrorToast: true },
  });

  const denyMutation = useMutation({
    mutationFn: async () => {
      await claimDeviceCode(userCode);
      const result = await authClient.device.deny({ userCode });
      if (result.error) {
        throw new Error(result.error.error_description ?? "Failed to deny");
      }
      return result.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: orpc.devices.key() });
      setDecision("denied");
      toast.success(t("device.denySuccess"));
    },
    onError: (err) => {
      console.error("[device.deny]", err);
      toast.error(friendly(err, t("device.denyError")));
    },
    meta: { skipGlobalErrorToast: true },
  });

  if (!userCode) {
    return (
      <DeviceShell>
        <CardHeader>
          <CardTitle>{t("device.enterCodeTitle")}</CardTitle>
          <CardDescription>
            <Trans i18nKey="device.enterCodeDescription" t={t} components={[<code key="0" />]} />
          </CardDescription>
        </CardHeader>
      </DeviceShell>
    );
  }

  if (decision === "approved") {
    return (
      <DeviceShell>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ShieldCheck className="size-5 text-emerald-600" /> {t("device.approved.title")}
          </CardTitle>
          <CardDescription>{t("device.approved.description")}</CardDescription>
        </CardHeader>
        <CardContent>
          <Link
            to={isCliDevice ? "/$lang/instances" : "/$lang/admin/devices"}
            params={{ lang }}
            className="inline-flex min-h-[44px] items-center rounded-md border px-4 py-2 text-sm font-medium hover:bg-muted"
          >
            {isCliDevice ? t("device.approved.viewInstances") : t("device.approved.viewActive")}
          </Link>
        </CardContent>
      </DeviceShell>
    );
  }

  if (decision === "denied") {
    return (
      <DeviceShell>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ShieldX className="size-5 text-destructive" /> {t("device.denied.title")}
          </CardTitle>
          <CardDescription>{t("device.denied.description")}</CardDescription>
        </CardHeader>
      </DeviceShell>
    );
  }

  return (
    <DeviceShell>
      <CardHeader>
        <CardTitle>{t("device.approveTitle")}</CardTitle>
        <CardDescription>
          {isCliDevice ? t("device.cliApproveDescription") : t("device.approveDescription")}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="rounded-md border bg-muted/40 px-3 py-2 font-mono text-sm">
          {t("device.userCodeLabel")} <strong>{userCode}</strong>
        </div>
        <div className="flex gap-2">
          <Button
            type="button"
            className="min-h-[44px]"
            onClick={() => approveMutation.mutate()}
            disabled={approveMutation.isPending || denyMutation.isPending}
          >
            {approveMutation.isPending ? t("device.approving") : t("device.approve")}
          </Button>
          <Button
            type="button"
            variant="outline"
            className="min-h-[44px]"
            onClick={() => denyMutation.mutate()}
            disabled={approveMutation.isPending || denyMutation.isPending}
          >
            {denyMutation.isPending ? t("device.denying") : t("device.deny")}
          </Button>
        </div>
      </CardContent>
    </DeviceShell>
  );
}

async function claimDeviceCode(userCode: string) {
  const url = new URL("/api/auth/device", env.VITE_SERVER_URL);
  url.searchParams.set("user_code", userCode);
  const response = await fetch(url, { credentials: "include" });
  if (!response.ok) throw new Error("Failed to claim device code");
}

function DeviceShell({ children }: { children: React.ReactNode }) {
  return (
    <div className="container mx-auto flex min-h-[80vh] max-w-md items-center px-4 py-8">
      <Card className="w-full">{children}</Card>
    </div>
  );
}
