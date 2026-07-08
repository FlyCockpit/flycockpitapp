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
import { Label } from "@flycockpit/ui/components/label";
import { toast } from "@flycockpit/ui/components/sileo";
import { Switch } from "@flycockpit/ui/components/switch";
import { useForm } from "@tanstack/react-form";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import type { TFunction } from "i18next";
import { Bell, BellOff } from "lucide-react";
import { useTranslation } from "react-i18next";
import z from "zod";

import { usePushNotifications } from "@/hooks/use-push-notifications";
import { useNamespaceT } from "@/i18n/use-namespace-t";
import { authClient } from "@/lib/auth-client";
import { friendly } from "@/utils/friendly-error";
import { orpc } from "@/utils/orpc";

export const Route = createFileRoute("/$lang/_auth/settings/")({
  component: ProfileSettings,
});

const NOTIFICATION_TYPE_KEYS = {
  QUESTION_RAISED: "questionRaised",
  APPROVAL_NEEDED: "approvalNeeded",
  TURN_DONE: "turnDone",
  TURN_ERROR: "turnError",
  SCHEDULE_DONE: "scheduleDone",
} as const;

function buildProfileSchema(t: TFunction<"settings">) {
  return z.object({
    name: z.string().min(2, t("profile.minLength")),
  });
}

function hasAdminRole(role: string | null | undefined): boolean {
  return (role ?? "")
    .split(",")
    .map((part) => part.trim())
    .includes("admin");
}

function ProfileSettings() {
  const { session } = Route.useRouteContext();
  const { t } = useTranslation(["settings", "auth", "common"]);
  const tSettings = useNamespaceT("settings");
  const queryClient = useQueryClient();
  const notificationPrefs = useQuery(orpc.settings.myNotificationPreferences.queryOptions());
  const cockpitNotificationPrefs = useQuery(orpc.notifications.myPreferences.queryOptions());
  const instances = useQuery(orpc.instances.listMine.queryOptions());
  const push = usePushNotifications();

  const updateNotificationPrefs = useMutation(
    orpc.settings.updateMyNotificationPreferences.mutationOptions({
      onSuccess: () => {
        queryClient.invalidateQueries({
          queryKey: orpc.settings.myNotificationPreferences.queryKey(),
        });
        toast.success(t("settings:profile.notificationsSaved"));
      },
      onError: () => {
        toast.error(t("settings:profile.notificationsSaveError"));
      },
    }),
  );

  const updateCockpitNotificationPrefs = useMutation(
    orpc.notifications.updateMyPreferences.mutationOptions({
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: orpc.notifications.myPreferences.queryKey() });
        toast.success(t("settings:profile.notificationsSaved"));
      },
      onError: () => {
        toast.error(t("settings:profile.notificationsSaveError"));
      },
    }),
  );

  const form = useForm({
    defaultValues: {
      name: session.user.name || "",
    },
    onSubmit: async ({ value }) => {
      const result = await authClient.updateUser({
        name: value.name,
      });
      if (result.error) {
        console.error("[settings.updateUser]", result.error);
        toast.error(friendly(result.error, t("settings:profile.saveError")));
        return;
      }
      toast.success(t("settings:profile.saved"));
    },
    validators: {
      onSubmit: buildProfileSchema(tSettings),
    },
  });

  const cockpitPrefs = cockpitNotificationPrefs.data;
  const instanceSettings = new Map(
    cockpitPrefs?.instances.map((setting) => [setting.instanceId, setting]) ?? [],
  );

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("settings:profile.title")}</CardTitle>
        <CardDescription>{t("settings:profile.description")}</CardDescription>
      </CardHeader>
      <CardContent>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            e.stopPropagation();
            form.handleSubmit();
          }}
          className="space-y-4"
        >
          <div className="space-y-2">
            <Label>{t("auth:fields.email")}</Label>
            <Input value={session.user.email} disabled />
            <p className="text-xs text-muted-foreground">{t("settings:profile.emailReadonly")}</p>
          </div>

          <form.Field name="name">
            {(field) => (
              <div className="space-y-2">
                <Label htmlFor={field.name}>{t("auth:fields.name")}</Label>
                <Input
                  id={field.name}
                  name={field.name}
                  autoComplete="name"
                  value={field.state.value}
                  onBlur={field.handleBlur}
                  onChange={(e) => field.handleChange(e.target.value)}
                />
                {field.state.meta.errors.map((error) => (
                  <p key={error?.message} className="text-sm text-destructive">
                    {error?.message}
                  </p>
                ))}
              </div>
            )}
          </form.Field>

          <form.Subscribe
            selector={(state) => ({
              canSubmit: state.canSubmit,
              isSubmitting: state.isSubmitting,
            })}
          >
            {({ canSubmit, isSubmitting }) => (
              <Button type="submit" disabled={!canSubmit || isSubmitting}>
                {isSubmitting ? t("common:actions.saving") : t("common:actions.saveChanges")}
              </Button>
            )}
          </form.Subscribe>
        </form>

        <div className="mt-6 space-y-5 border-t pt-6">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
            <div className="space-y-1">
              <h2 className="font-medium text-sm">{t("settings:profile.cockpitNotifications")}</h2>
              <p className="text-sm text-muted-foreground">
                {t("settings:profile.cockpitNotificationsDescription")}
              </p>
            </div>
            <Switch
              checked={cockpitPrefs?.notificationAlerts ?? true}
              disabled={
                cockpitNotificationPrefs.isPending || updateCockpitNotificationPrefs.isPending
              }
              onCheckedChange={(checked) =>
                updateCockpitNotificationPrefs.mutate({ notificationAlerts: checked === true })
              }
              aria-label={t("settings:profile.cockpitNotifications")}
            />
          </div>

          <div className="flex flex-col gap-3 rounded-md border p-3 sm:flex-row sm:items-center sm:justify-between">
            <div className="space-y-1">
              <p className="font-medium text-sm">{t("settings:profile.webPush")}</p>
              <p className="text-sm text-muted-foreground">
                {push.isSupported
                  ? t("settings:profile.webPushDescription", { permission: push.permission })
                  : t("settings:profile.webPushUnsupported")}
              </p>
            </div>
            <div className="flex gap-2">
              <Button
                type="button"
                variant="outline"
                disabled={!push.isSupported || push.isSubscribing}
                onClick={push.subscribe}
              >
                <Bell className="size-4" />
                {t("settings:profile.webPushSubscribe")}
              </Button>
              <Button
                type="button"
                variant="outline"
                disabled={!push.isSupported || push.isUnsubscribing}
                onClick={push.unsubscribe}
              >
                <BellOff className="size-4" />
                {t("settings:profile.webPushUnsubscribe")}
              </Button>
            </div>
          </div>

          <div className="grid gap-3 md:grid-cols-2">
            {cockpitPrefs?.types.map((pref) => {
              const labelKey =
                NOTIFICATION_TYPE_KEYS[pref.type as keyof typeof NOTIFICATION_TYPE_KEYS];
              return (
                <div
                  key={pref.type}
                  className="flex items-center justify-between rounded-md border p-3"
                >
                  <Label className="text-sm" htmlFor={`notification-type-${pref.type}`}>
                    {t(`settings:profile.notificationTypes.${labelKey}`)}
                  </Label>
                  <Switch
                    id={`notification-type-${pref.type}`}
                    checked={pref.enabled}
                    disabled={updateCockpitNotificationPrefs.isPending}
                    onCheckedChange={(checked) =>
                      updateCockpitNotificationPrefs.mutate({
                        types: [{ type: pref.type, enabled: checked === true }],
                      })
                    }
                  />
                </div>
              );
            })}
          </div>

          {instances.data?.instances.length ? (
            <div className="space-y-3">
              <p className="font-medium text-sm">{t("settings:profile.instanceNotifications")}</p>
              <div className="space-y-2">
                {instances.data.instances.map((instance) => {
                  const setting = instanceSettings.get(instance.id);
                  return (
                    <div key={instance.id} className="rounded-md border p-3">
                      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                        <div>
                          <p className="font-medium text-sm">{instance.displayName}</p>
                          <p className="text-xs text-muted-foreground">{instance.hostname}</p>
                        </div>
                        <div className="flex flex-wrap gap-4">
                          <Label className="flex items-center gap-2 text-sm">
                            <Switch
                              size="sm"
                              checked={setting?.muted ?? false}
                              disabled={updateCockpitNotificationPrefs.isPending}
                              onCheckedChange={(checked) =>
                                updateCockpitNotificationPrefs.mutate({
                                  instances: [{ instanceId: instance.id, muted: checked === true }],
                                })
                              }
                            />
                            {t("settings:profile.muteInstance")}
                          </Label>
                          <Label className="flex items-center gap-2 text-sm">
                            <Switch
                              size="sm"
                              checked={setting?.ownerReceivesSharedSessions ?? false}
                              disabled={updateCockpitNotificationPrefs.isPending}
                              onCheckedChange={(checked) =>
                                updateCockpitNotificationPrefs.mutate({
                                  instances: [
                                    {
                                      instanceId: instance.id,
                                      ownerReceivesSharedSessions: checked === true,
                                    },
                                  ],
                                })
                              }
                            />
                            {t("settings:profile.ownerSharedSessions")}
                          </Label>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          ) : null}
        </div>

        {hasAdminRole(session.user.role) ? (
          <div className="mt-6 border-t pt-6">
            <div className="flex items-start gap-3">
              <Checkbox
                id="operational-alerts"
                checked={notificationPrefs.data?.operationalAlerts ?? true}
                disabled={notificationPrefs.isPending || updateNotificationPrefs.isPending}
                onCheckedChange={(checked) => {
                  updateNotificationPrefs.mutate({ operationalAlerts: checked === true });
                }}
              />
              <div className="space-y-1">
                <Label htmlFor="operational-alerts">
                  {t("settings:profile.operationalAlerts")}
                </Label>
                <p className="text-sm text-muted-foreground">
                  {t("settings:profile.operationalAlertsDescription")}
                </p>
              </div>
            </div>
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
}
