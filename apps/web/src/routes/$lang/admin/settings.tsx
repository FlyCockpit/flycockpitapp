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
import type { TFunction } from "i18next";
import { Server, Shield } from "lucide-react";
import { useTranslation } from "react-i18next";

import { InlineRetry } from "@/components/inline-retry";
import { orpc } from "@/utils/orpc";

type ForceTwoFactorSettingKey = "force2faPublicUsers" | "force2faInternalUsers";

export const Route = createFileRoute("/$lang/admin/settings")({
  component: AdminSettings,
});

function AdminSettings() {
  const { session } = Route.useRouteContext();
  const queryClient = useQueryClient();
  const appSettings = useQuery(orpc.settings.getAll.queryOptions());
  const deploymentProfile = useQuery(orpc.entitlements.deploymentProfile.queryOptions());
  const adminHas2FA = session.user.twoFactorEnabled === true;
  const { t } = useTranslation(["admin", "common"]);

  const updateSetting = useMutation({
    ...orpc.settings.update.mutationOptions({
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: orpc.settings.key() });
      },
    }),
    meta: { errorFallbackKey: "admin:settings.updateFailed" },
  });

  return (
    <div className="container mx-auto max-w-4xl px-4 py-8 space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">{t("admin:settings.title")}</h1>
        <p className="mt-2 text-muted-foreground">{t("admin:settings.description")}</p>
      </div>

      {deploymentProfile.data && <DeploymentProfileCard profile={deploymentProfile.data} />}

      {appSettings.isPending ? (
        <SettingsSkeleton />
      ) : appSettings.isError ? (
        <Card>
          <CardContent>
            <InlineRetry
              className="py-12"
              message={t("admin:settings.loadFailed")}
              onRetry={() => appSettings.refetch()}
            />
          </CardContent>
        </Card>
      ) : (
        <SecurityPolicyCard
          policies={[
            {
              key: "force2faInternalUsers",
              enabled:
                (appSettings.data.force2faInternalUsers ?? appSettings.data.force2fa) === "true",
              title: t("admin:settings.force2faInternalTitle"),
              description: t("admin:settings.force2faInternalDescription"),
            },
            {
              key: "force2faPublicUsers",
              enabled:
                (appSettings.data.force2faPublicUsers ?? appSettings.data.force2fa) === "true",
              title: t("admin:settings.force2faPublicTitle"),
              description: t("admin:settings.force2faPublicDescription"),
            },
          ]}
          adminHas2FA={adminHas2FA}
          isUpdating={updateSetting.isPending}
          onToggle={(key, newValue) => {
            updateSetting.mutate(
              { key, value: newValue },
              {
                onSuccess: () => {
                  toast.success(successMessageForForceTwoFactor(t, key, newValue));
                },
              },
            );
          }}
        />
      )}
    </div>
  );
}

function DeploymentProfileCard({
  profile,
}: {
  profile: {
    profile: "hosted" | "enterprise" | "oss";
    productName: string;
    version: string;
    nativeAppEligible: boolean;
    enterpriseLicense?: { org: string; expiresAt: Date | string; valid: boolean };
  };
}) {
  const { t } = useTranslation("admin");
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Server className="size-5" />
          {t("settings.deploymentTitle")}
        </CardTitle>
        <CardDescription>{t("settings.deploymentDescription")}</CardDescription>
      </CardHeader>
      <CardContent className="grid gap-3 text-sm sm:grid-cols-2">
        <ProfileDatum label={t("settings.deploymentProfileLabel")} value={profile.profile} />
        <ProfileDatum label={t("settings.deploymentProductLabel")} value={profile.productName} />
        <ProfileDatum label={t("settings.deploymentVersionLabel")} value={profile.version} />
        <ProfileDatum
          label={t("settings.deploymentNativeLabel")}
          value={profile.nativeAppEligible ? t("settings.enabled") : t("settings.disabled")}
        />
        {profile.enterpriseLicense && (
          <>
            <ProfileDatum
              label={t("settings.enterpriseOrgLabel")}
              value={profile.enterpriseLicense.org}
            />
            <ProfileDatum
              label={t("settings.enterpriseLicenseLabel")}
              value={
                profile.enterpriseLicense.valid
                  ? t("settings.enterpriseLicenseValid")
                  : t("settings.enterpriseLicenseInvalid")
              }
            />
          </>
        )}
      </CardContent>
    </Card>
  );
}

function ProfileDatum({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border p-3">
      <p className="text-xs font-medium uppercase text-muted-foreground">{label}</p>
      <p className="mt-1 font-medium">{value}</p>
    </div>
  );
}

function SecurityPolicyCard({
  policies,
  adminHas2FA,
  isUpdating,
  onToggle,
}: {
  policies: Array<{
    key: ForceTwoFactorSettingKey;
    enabled: boolean;
    title: string;
    description: string;
  }>;
  adminHas2FA: boolean;
  isUpdating: boolean;
  onToggle: (key: ForceTwoFactorSettingKey, newValue: "true" | "false") => void;
}) {
  const { t } = useTranslation("admin");
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Shield className="size-5" />
          {t("settings.securityTitle")}
        </CardTitle>
        <CardDescription>{t("settings.securityDescription")}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {!adminHas2FA && (
          <p className="text-sm text-destructive">{t("settings.force2faAdminWarning")}</p>
        )}
        {policies.map((policy) => (
          <div
            key={policy.key}
            className="flex items-start justify-between gap-4 rounded-lg border p-4"
          >
            <div className="space-y-1">
              <p className="font-medium">{policy.title}</p>
              <p className="text-sm text-muted-foreground">{policy.description}</p>
            </div>
            <Button
              variant={policy.enabled ? "destructive" : "default"}
              size="sm"
              className="min-h-[44px]"
              disabled={(!adminHas2FA && !policy.enabled) || isUpdating}
              onClick={() => onToggle(policy.key, policy.enabled ? "false" : "true")}
            >
              {isUpdating
                ? t("settings.updating")
                : policy.enabled
                  ? t("settings.disable")
                  : t("settings.enable")}
            </Button>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

function successMessageForForceTwoFactor(
  t: TFunction<["admin", "common"]>,
  key: ForceTwoFactorSettingKey,
  value: "true" | "false",
): string {
  if (key === "force2faInternalUsers") {
    return value === "true"
      ? t("admin:settings.force2faInternalEnabled")
      : t("admin:settings.force2faInternalDisabled");
  }
  return value === "true"
    ? t("admin:settings.force2faPublicEnabled")
    : t("admin:settings.force2faPublicDisabled");
}

function SettingsSkeleton() {
  const { t } = useTranslation("admin");
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Shield className="size-5" />
          <span className="sr-only">{t("settings.securityTitle")}</span>
          <Skeleton className="h-5 w-32" />
        </CardTitle>
        <CardDescription>
          <Skeleton className="h-4 w-64" />
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {["internal", "public"].map((policy) => (
          <div
            key={policy}
            className="flex items-start justify-between gap-4 rounded-lg border p-4"
          >
            <div className="flex-1 space-y-2">
              <Skeleton className="h-5 w-56" />
              <Skeleton className="h-4 w-full max-w-md" />
              <Skeleton className="h-4 w-3/4" />
            </div>
            <Skeleton className="h-9 w-20" />
          </div>
        ))}
      </CardContent>
    </Card>
  );
}
