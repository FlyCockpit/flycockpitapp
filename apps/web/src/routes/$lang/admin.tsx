import { hasRole } from "@flycockpit/auth/roles";
import { cn } from "@flycockpit/ui/lib/utils";
import { createFileRoute, Link, notFound, Outlet } from "@tanstack/react-router";
import {
  Building2,
  Database,
  Image,
  KeyRound,
  LayoutDashboard,
  ListX,
  Settings,
  Smartphone,
  Users,
  Video,
} from "lucide-react";
import { useTranslation } from "react-i18next";

import { authClient } from "@/lib/auth-client";

export const Route = createFileRoute("/$lang/admin")({
  beforeLoad: async () => {
    const session = await authClient.getSession();
    // 404-hide the entire admin tree from non-admins. Throwing notFound()
    // (instead of redirect) means an unauthorized visitor can't tell whether
    // /admin exists at all — same response as a route that doesn't exist.
    // Narrow session.data here so children inherit a non-null `session`
    // and can call hooks without an early-return guard.
    const sessionData = session.data;
    const user = sessionData?.user;
    if (!sessionData || !user?.emailVerified || !hasRole(user.role, "admin")) {
      throw notFound();
    }
    return { session: sessionData };
  },
  component: AdminLayout,
});

function AdminLayout() {
  return (
    <div className="min-h-screen">
      <AdminNav />
      <Outlet />
    </div>
  );
}

function AdminNav() {
  const { lang } = Route.useParams();
  const { t } = useTranslation("admin");
  const NAV_ITEMS = [
    {
      to: "/$lang/admin" as const,
      label: t("nav.overview"),
      icon: LayoutDashboard,
      exact: true,
    },
    {
      to: "/$lang/admin/assets" as const,
      label: t("nav.assets"),
      icon: Image,
      exact: false,
    },
    {
      to: "/$lang/admin/videos" as const,
      label: t("nav.videos"),
      icon: Video,
      exact: false,
    },
    {
      to: "/$lang/admin/users" as const,
      label: t("nav.users"),
      icon: Users,
      exact: false,
    },
    {
      to: "/$lang/admin/api-keys" as const,
      label: t("nav.apiKeys"),
      icon: KeyRound,
      exact: false,
    },
    {
      to: "/$lang/admin/devices" as const,
      label: t("nav.devices"),
      icon: Smartphone,
      exact: false,
    },
    {
      to: "/$lang/admin/jobs" as const,
      label: t("nav.jobs"),
      icon: ListX,
      exact: false,
    },
    {
      to: "/$lang/admin/enterprise" as const,
      label: t("nav.enterprise"),
      icon: Building2,
      exact: false,
    },
    {
      to: "/$lang/admin/settings" as const,
      label: t("nav.settings"),
      icon: Settings,
      exact: false,
    },
    {
      to: "/$lang/admin/seed" as const,
      label: t("nav.seed"),
      icon: Database,
      exact: false,
    },
  ];
  return (
    <nav
      aria-label={t("nav.ariaLabel")}
      className="sticky top-0 z-30 border-b bg-background/80 backdrop-blur"
    >
      <div className="container mx-auto min-w-0 max-w-7xl">
        <ul className="-mb-px flex gap-1 overflow-x-auto no-scrollbar px-4 py-2">
          {NAV_ITEMS.map((item) => (
            <li key={item.to} className="shrink-0">
              <Link
                to={item.to}
                params={{ lang }}
                activeOptions={{ exact: item.exact }}
                className={cn(
                  "inline-flex min-h-[44px] shrink-0 items-center gap-2 whitespace-nowrap rounded-md px-3 py-2 text-sm font-medium text-muted-foreground transition-colors hover:bg-muted hover:text-foreground",
                )}
                activeProps={{
                  className: "bg-muted text-foreground",
                }}
              >
                <item.icon aria-hidden="true" className="size-4" />
                <span>{item.label}</span>
              </Link>
            </li>
          ))}
        </ul>
      </div>
    </nav>
  );
}
