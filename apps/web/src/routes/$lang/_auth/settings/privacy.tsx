import { Button } from "@flycockpit/ui/components/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@flycockpit/ui/components/card";
import { createFileRoute } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";

import { useConsent } from "@/hooks/use-consent";
import { OPTIONAL_CATEGORIES } from "@/lib/consent";
import { useConsentUi } from "@/stores/consent-ui";

export const Route = createFileRoute("/$lang/_auth/settings/privacy")({
  component: PrivacySettings,
});

function PrivacySettings() {
  const { t, i18n } = useTranslation("consent");
  const { hasDecision, consent, record } = useConsent();
  const openPreferences = useConsentUi((s) => s.openPreferences);

  const status =
    hasDecision && record
      ? t("consent:settings.statusDecided", {
          date: new Intl.DateTimeFormat(i18n.language, {
            dateStyle: "medium",
            timeStyle: "short",
          }).format(new Date(record.ts)),
        })
      : t("consent:settings.statusUndecided");

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("consent:settings.title")}</CardTitle>
        <CardDescription>{t("consent:settings.description")}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <p className="text-xs text-muted-foreground">{status}</p>

        <dl className="divide-y rounded-lg ring-1 ring-foreground/10">
          <div className="flex items-center justify-between gap-4 px-4 py-3">
            <dt className="text-sm font-medium">{t("consent:categories.necessary.name")}</dt>
            <dd className="text-xs font-medium text-muted-foreground">
              {t("consent:categories.alwaysOn")}
            </dd>
          </div>
          {OPTIONAL_CATEGORIES.map((category) => (
            <div key={category} className="flex items-center justify-between gap-4 px-4 py-3">
              <dt className="text-sm font-medium">{t(`consent:categories.${category}.name`)}</dt>
              <dd
                className={
                  consent[category]
                    ? "text-xs font-medium text-primary"
                    : "text-xs font-medium text-muted-foreground"
                }
              >
                {consent[category] ? t("status.enabled") : t("status.disabled")}
              </dd>
            </div>
          ))}
        </dl>

        <Button className="min-h-[44px]" onClick={openPreferences}>
          {t("consent:settings.manageButton")}
        </Button>
      </CardContent>
    </Card>
  );
}
