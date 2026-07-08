import { buttonVariants } from "@flycockpit/ui/components/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@flycockpit/ui/components/card";
import { cn } from "@flycockpit/ui/lib/utils";
import { createFileRoute, Link } from "@tanstack/react-router";
import {
  Building2,
  HardDrive,
  KeyRound,
  ListX,
  Settings,
  Smartphone,
  Users,
  Video,
} from "lucide-react";
import { useTranslation } from "react-i18next";

export const Route = createFileRoute("/$lang/admin/")({
  component: AdminOverview,
});

function AdminOverview() {
  const { lang } = Route.useParams();
  const { t } = useTranslation(["admin", "common"]);

  const quickLinks = [
    {
      to: "/$lang/admin/enterprise" as const,
      label: t("admin:nav.enterprise"),
      hint: t("admin:overview.quickLink.enterpriseHint"),
      icon: Building2,
    },
    {
      to: "/$lang/admin/users" as const,
      label: t("admin:nav.users"),
      hint: t("admin:overview.quickLink.usersHint"),
      icon: Users,
    },
    {
      to: "/$lang/admin/devices" as const,
      label: t("admin:nav.devices"),
      hint: t("admin:overview.quickLink.devicesHint"),
      icon: Smartphone,
    },
    {
      to: "/$lang/admin/assets" as const,
      label: t("admin:nav.assets"),
      hint: t("admin:overview.quickLink.assetsHint"),
      icon: HardDrive,
    },
    {
      to: "/$lang/admin/videos" as const,
      label: t("admin:nav.videos"),
      hint: t("admin:overview.quickLink.videosHint"),
      icon: Video,
    },
    {
      to: "/$lang/admin/api-keys" as const,
      label: t("admin:nav.apiKeys"),
      hint: t("admin:overview.quickLink.apiKeysHint"),
      icon: KeyRound,
    },
    {
      to: "/$lang/admin/jobs" as const,
      label: t("admin:nav.jobs"),
      hint: t("admin:overview.quickLink.jobsHint"),
      icon: ListX,
    },
    {
      to: "/$lang/admin/settings" as const,
      label: t("admin:nav.settings"),
      hint: t("admin:overview.quickLink.settingsHint"),
      icon: Settings,
    },
  ];

  return (
    <div className="container mx-auto max-w-7xl px-4 py-8">
      <header className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">{t("admin:overview.title")}</h1>
        <p className="text-sm text-muted-foreground">{t("admin:overview.description")}</p>
      </header>

      <section className="mt-8 grid grid-cols-12 gap-4">
        {quickLinks.map((item) => (
          <Card key={item.to} className="col-span-12 sm:col-span-6 lg:col-span-3">
            <CardHeader className="flex flex-row items-start justify-between gap-3 pb-2">
              <div>
                <CardTitle className="text-base">{item.label}</CardTitle>
                <CardDescription className="mt-1">{item.hint}</CardDescription>
              </div>
              <item.icon aria-hidden className="size-5 shrink-0 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <Link
                to={item.to}
                params={{ lang }}
                className={cn(buttonVariants({ variant: "outline", size: "sm" }), "min-h-[44px]")}
              >
                {t("common:actions.open")}
              </Link>
            </CardContent>
          </Card>
        ))}
      </section>
    </div>
  );
}
